//! Resolve-check subcommand.
//!
//! Given a directory or `Cargo.toml` file, verify that Cargo can
//! successfully resolve (generate a lockfile) using only the TakoPack
//! local directory registry in offline mode.
//!
//! Uses the Cargo API (`Workspace`, `ops::generate_lockfile`) directly
//! rather than spawning an external `cargo` process.
//!
//! ## Current limitations (MVP)
//!
//! * Virtual mode copies only `Cargo.toml` and creates stub target files
//!   in a temp directory.  Workspace manifests, path dependencies, and
//!   build scripts that reference sibling files will not resolve.
//! * Real mode operates on the original directory; Cargo may create or
//!   update `Cargo.lock` there.
//! * Plain resolve-check still prints raw Cargo API errors.  The experimental
//!   plan-missing mode performs limited structured analysis for missing crates
//!   and version conflicts.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use cargo::core::Workspace;
use cargo::ops;
use cargo::util::GlobalContext;
use regex::Regex;
use semver::Version;
use serde_derive::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::cli::PlanSessionStorage;
use crate::config::load_takopack_toml;
use crate::crates::resolve_crates_io_version_req;
use crate::errors::Result;
use crate::registry_sync::materialize_crate_from_crates_io;
use crate::util::{calculate_compat_version, rust_crate_output_names};

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct ResolveOutcome {
    buildrequires: Vec<String>,
}

#[derive(Debug)]
struct PreparedResolveProject {
    manifest: PathBuf,
    _tmp_project: Option<tempfile::TempDir>,
}

#[derive(Debug)]
struct OverlayRegistry {
    registry_dir: PathBuf,
    superseded_dir: PathBuf,
    _tempdir: Option<tempfile::TempDir>,
    unmount_on_drop: bool,
    session_name: Option<String>,
    session_root: Option<PathBuf>,
    session_file: Option<PathBuf>,
    state: PlanSessionState,
    stats: OverlayCopyStats,
}

#[derive(Debug, Default)]
struct OverlayCopyStats {
    hardlinked_files: usize,
    copied_files: usize,
    reflinked_files: usize,
}

/// The actual storage method used after mode resolution (e.g. auto → copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResolvedStorageMethod {
    FuseOverlay,
    Reflink,
    Copy,
    Hardlink,
}

#[derive(Debug, Clone)]
struct MissingPackageError {
    crate_name: String,
    required_by: Option<RequiredByPackage>,
}

#[derive(Debug, Clone)]
struct RequiredByPackage {
    name: String,
    version: String,
    path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
struct ExistingProvider {
    provider_name: String,
    version: String,
    compat: String,
}

#[derive(Debug, Clone)]
struct PlannedAdd {
    crate_name: String,
    version: Version,
}

#[derive(Debug, Clone)]
struct PlannedUpgrade {
    crate_name: String,
    version: Version,
}

#[derive(Debug, Clone)]
struct VersionSelectionFailure {
    crate_name: String,
    requirement: String,
    required_by: Option<RequiredByPackage>,
}

#[derive(Debug, Clone)]
struct UpgradeCandidate {
    crate_name: String,
    requirement: String,
    required_by: Option<RequiredByPackage>,
    candidate_version: Version,
    candidate_provider_name: String,
    existing: Vec<ExistingProvider>,
}

#[derive(Debug, Clone)]
struct PlanActionResult {
    key: String,
    changed: bool,
    last_action: String,
}

#[derive(Debug, Clone)]
enum VersionSelectionPlan {
    Continue(PlanActionResult),
    Stopped(UpgradeCandidate),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PlanSessionState {
    schema_version: u32,
    base_registry: String,
    #[serde(default)]
    registry_storage: Option<String>,
    #[serde(default)]
    session_registry: Option<String>,
    #[serde(default)]
    overlay_upper: Option<String>,
    #[serde(default)]
    overlay_work: Option<String>,
    #[serde(default)]
    added_crates: Vec<AddedCrateRecord>,
    #[serde(default)]
    upgraded_crates: Vec<UpgradedCrateRecord>,
    #[serde(default)]
    last_result: Option<String>,
    #[serde(default)]
    last_stop_reason: Option<String>,
    #[serde(default)]
    last_iterations: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
struct AddedCrateRecord {
    crate_name: String,
    version: String,
    rpm_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
struct UpgradedCrateRecord {
    crate_name: String,
    from_version: String,
    to_version: String,
    rpm_name: String,
    required_by: String,
    requirement: String,
}

/// Run the `resolve-check` subcommand.
///
/// Returns an exit code: 0 = resolve succeeded, 1 = failed or error.
pub fn run_resolve_check(
    path: &Path,
    no_dev: bool,
    print_buildrequires: bool,
    plan_missing: bool,
    plan_session: Option<&str>,
    plan_reset: bool,
    plan_add: &[String],
    plan_upgrade: &[String],
    allow_session_upgrades: bool,
    max_plan_iterations: usize,
    plan_progress_interval: usize,
    plan_summary_only: bool,
    plan_session_storage: PlanSessionStorage,
) -> Result<i32> {
    if !plan_missing
        && (plan_session.is_some()
            || plan_reset
            || !plan_add.is_empty()
            || !plan_upgrade.is_empty()
            || allow_session_upgrades
            || plan_summary_only)
    {
        takopack_bail!(
            "--plan-session, --plan-reset, --plan-add, --plan-upgrade, --allow-session-upgrades, and --plan-summary-only require --plan-missing"
        );
    }
    if plan_reset && plan_session.is_none() {
        takopack_bail!("--plan-reset requires --plan-session <NAME>");
    }
    if plan_summary_only && plan_session.is_none() {
        takopack_bail!("--plan-summary-only requires --plan-session <NAME>");
    }
    if plan_summary_only
        && (plan_reset
            || !plan_add.is_empty()
            || !plan_upgrade.is_empty()
            || allow_session_upgrades)
    {
        takopack_bail!(
            "--plan-summary-only cannot be combined with --plan-reset, --plan-add, --plan-upgrade, or --allow-session-upgrades"
        );
    }

    // 1. Determine manifest path and working directory.
    let (manifest, workdir) = resolve_manifest(path)?;

    // 2. Determine registry directory.
    let registry_dir = resolve_registry_dir()?;
    if !registry_dir.is_dir() {
        takopack_bail!(
            "local registry directory does not exist: {}\n\
             Run `takopack cargo registry-sync` first.",
            registry_dir.display()
        );
    }

    // 3. Parse targets from the manifest.
    let targets = parse_manifest_targets(&manifest)?;

    println!("Resolve check");
    println!("  manifest: {}", manifest.display());
    println!("  registry: {}", registry_dir.display());

    // 4. Decide mode based on whether declared targets exist on disk.
    let is_real = detect_real_mode(&targets, &workdir);

    println!("  mode: {}", if is_real { "real" } else { "virtual" });
    println!("  no_dev: {}", no_dev);
    if plan_missing {
        println!("  plan_missing: true");
        if let Some(name) = plan_session {
            println!("  plan_session: {}", name);
        }
        if max_plan_iterations == 0 {
            println!("  max_plan_iterations: unbounded");
        } else {
            println!("  max_plan_iterations: {}", max_plan_iterations);
        }
    }
    println!();

    if plan_summary_only {
        return run_plan_summary_only(plan_session.expect("validated plan session"));
    }

    if plan_missing {
        return run_resolve_check_plan_missing(
            &manifest,
            &workdir,
            &registry_dir,
            &targets,
            is_real,
            no_dev,
            print_buildrequires,
            plan_session,
            plan_reset,
            plan_add,
            plan_upgrade,
            allow_session_upgrades,
            max_plan_iterations,
            plan_progress_interval,
            plan_session_storage,
        );
    }

    if is_real {
        match cargo_resolve(
            &manifest,
            &workdir,
            &registry_dir,
            no_dev,
            print_buildrequires,
        ) {
            Ok(outcome) => {
                println!("Result: ok");
                print_buildrequires_if_requested(print_buildrequires, &outcome.buildrequires);
                Ok(0)
            }
            Err(e) => {
                println!("Result: failed");
                eprintln!("{:?}", e);
                Ok(1)
            }
        }
    } else {
        match cargo_resolve_virtual_with_options(
            &manifest,
            &registry_dir,
            &targets,
            no_dev,
            print_buildrequires,
        ) {
            Ok(outcome) => {
                println!("Result: ok");
                print_buildrequires_if_requested(print_buildrequires, &outcome.buildrequires);
                Ok(0)
            }
            Err(e) => {
                println!("Result: failed");
                eprintln!("{:?}", e);
                Ok(1)
            }
        }
    }
}

fn print_buildrequires_if_requested(print_buildrequires: bool, buildrequires: &[String]) {
    if !print_buildrequires {
        return;
    }

    println!();
    println!("BuildRequires:");
    for line in buildrequires {
        println!("{}", line);
    }
}

// ---------------------------------------------------------------------------
// plan-missing mode
// ---------------------------------------------------------------------------

fn run_resolve_check_plan_missing(
    manifest: &Path,
    workdir: &Path,
    registry_dir: &Path,
    targets: &ManifestTargets,
    is_real: bool,
    no_dev: bool,
    print_buildrequires: bool,
    plan_session: Option<&str>,
    plan_reset: bool,
    plan_add: &[String],
    plan_upgrade: &[String],
    allow_session_upgrades: bool,
    max_plan_iterations: usize,
    plan_progress_interval: usize,
    plan_session_storage: PlanSessionStorage,
) -> Result<i32> {
    println!("Planning missing providers using overlay registry...");
    println!();

    let mut overlay =
        create_overlay_registry(registry_dir, plan_session, plan_reset, plan_session_storage)?;
    log::debug!(
        "overlay registry: {} (hardlinked files: {}, copied files: {})",
        overlay.path().display(),
        overlay.stats.hardlinked_files,
        overlay.stats.copied_files
    );

    for add in plan_add {
        let add = parse_plan_add(add)?;
        add_crate_to_overlay(&mut overlay, &add.crate_name, &add.version)?;
    }
    for upgrade in plan_upgrade {
        let upgrade = parse_plan_upgrade(upgrade)?;
        apply_upgrade_to_overlay(
            &mut overlay,
            &upgrade.crate_name,
            &upgrade.version,
            "",
            None,
        )?;
    }

    let prepared = prepare_project_for_plan_missing(manifest, workdir, targets, is_real, no_dev)?;
    let mut action_keys = HashSet::new();
    let mut iterations = 0usize;
    let progress_interval = plan_progress_interval;

    loop {
        if max_plan_iterations != 0 && iterations >= max_plan_iterations {
            finish_plan_run(
                &mut overlay,
                "stopped",
                "max iterations reached",
                iterations,
            )?;
            println!("Result: stopped");
            println!("Reason: max iterations reached");
            return Ok(1);
        }

        iterations += 1;
        match cargo_resolve_prepared(&prepared.manifest, overlay.path(), print_buildrequires) {
            Ok(outcome) => {
                finish_plan_run(&mut overlay, "ok", "resolve ok", iterations)?;
                println!("Result: ok");
                print_buildrequires_if_requested(print_buildrequires, &outcome.buildrequires);
                return Ok(0);
            }
            Err(err) => {
                let error_text = format!("{:#}", err);
                if let Some(missing) = parse_missing_package_error(&error_text) {
                    match plan_and_materialize_missing_crate(
                        &missing,
                        &prepared.manifest,
                        &mut overlay,
                        no_dev,
                    ) {
                        Ok(action) => {
                            if let Some(reason) = detect_no_progress(&mut action_keys, &action) {
                                finish_plan_run(&mut overlay, "stopped", &reason, iterations)?;
                                println!("Result: stopped");
                                println!("Reason: {}", reason);
                                return Ok(1);
                            }
                            print_plan_progress_if_needed(
                                iterations,
                                progress_interval,
                                &overlay.state,
                                &action.last_action,
                            );
                            continue;
                        }
                        Err(plan_err) => {
                            finish_plan_run(
                                &mut overlay,
                                "failed",
                                "cargo error while planning missing provider",
                                iterations,
                            )?;
                            println!("Result: failed");
                            eprintln!("{:#}", plan_err);
                            return Ok(1);
                        }
                    }
                }

                if let Some(failure) = parse_version_selection_failure(&error_text) {
                    match plan_or_conflict_version_selection_failure(
                        &failure,
                        &mut overlay,
                        allow_session_upgrades,
                    ) {
                        Ok(VersionSelectionPlan::Continue(action)) => {
                            if let Some(reason) = detect_no_progress(&mut action_keys, &action) {
                                finish_plan_run(&mut overlay, "stopped", &reason, iterations)?;
                                println!("Result: stopped");
                                println!("Reason: {}", reason);
                                return Ok(1);
                            }
                            print_plan_progress_if_needed(
                                iterations,
                                progress_interval,
                                &overlay.state,
                                &action.last_action,
                            );
                            continue;
                        }
                        Ok(VersionSelectionPlan::Stopped(candidate)) => {
                            finish_plan_run(
                                &mut overlay,
                                "stopped",
                                "upgrade candidate requires confirmation",
                                iterations,
                            )?;
                            println!("Result: stopped");
                            println!();
                            print_upgrade_candidates(&[candidate.clone()]);
                            println!();
                            print_continue_with_upgrade_command(
                                manifest,
                                no_dev,
                                print_buildrequires,
                                plan_session,
                                &candidate,
                            );
                            return Ok(1);
                        }
                        Err(plan_err) => {
                            finish_plan_run(
                                &mut overlay,
                                "failed",
                                "cargo error while planning upgrade candidate",
                                iterations,
                            )?;
                            println!("Result: failed");
                            eprintln!("{:#}", plan_err);
                            return Ok(1);
                        }
                    }
                }

                finish_plan_run(&mut overlay, "failed", "unknown cargo failure", iterations)?;
                println!("Result: failed");
                println!();
                println!("Unknown failure:");
                eprintln!("{}", error_text);
                return Ok(1);
            }
        }
    }
}

impl OverlayRegistry {
    fn path(&self) -> &Path {
        &self.registry_dir
    }
}

impl Drop for OverlayRegistry {
    fn drop(&mut self) {
        if self.unmount_on_drop {
            unmount_session_registry_best_effort(&self.registry_dir);
        }
    }
}

impl PlanSessionState {
    fn new(base_registry: &Path) -> Self {
        Self {
            schema_version: 1,
            base_registry: base_registry.display().to_string(),
            registry_storage: None,
            session_registry: None,
            overlay_upper: None,
            overlay_work: None,
            added_crates: Vec::new(),
            upgraded_crates: Vec::new(),
            last_result: None,
            last_stop_reason: None,
            last_iterations: None,
        }
    }
}

fn prepare_project_for_plan_missing(
    manifest: &Path,
    workdir: &Path,
    targets: &ManifestTargets,
    is_real: bool,
    no_dev: bool,
) -> Result<PreparedResolveProject> {
    if is_real {
        let workdir = workdir
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", workdir.display()))?;
        let manifest = manifest
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", manifest.display()))?;
        let manifest_rel = manifest
            .strip_prefix(&workdir)
            .with_context(|| format!("{} is not under {}", manifest.display(), workdir.display()))?
            .to_path_buf();

        let tmp = tempfile::tempdir().context("failed to create plan-missing temporary project")?;
        copy_project_tree_for_resolve(&workdir, tmp.path())?;
        let tmp_manifest = tmp.path().join(manifest_rel);
        if no_dev {
            strip_dev_dependencies_from_project(tmp.path())?;
        }
        let tmp_manifest = tmp_manifest
            .canonicalize()
            .context("failed to canonicalize plan-missing temp manifest")?;

        return Ok(PreparedResolveProject {
            manifest: tmp_manifest,
            _tmp_project: Some(tmp),
        });
    }

    let tmp = tempfile::tempdir().context("failed to create plan-missing virtual project")?;
    let tmp_path = tmp.path();
    let tmp_manifest = tmp_path.join("Cargo.toml");
    fs::copy(manifest, &tmp_manifest)
        .with_context(|| format!("failed to copy {} to tempdir", manifest.display()))?;
    if no_dev {
        strip_dev_dependencies_from_manifest(&tmp_manifest)?;
    }
    create_virtual_stubs(tmp_path, targets)?;
    let tmp_manifest = tmp_manifest
        .canonicalize()
        .context("failed to canonicalize plan-missing virtual manifest")?;

    Ok(PreparedResolveProject {
        manifest: tmp_manifest,
        _tmp_project: Some(tmp),
    })
}

fn cargo_resolve_prepared(
    manifest: &Path,
    registry_dir: &Path,
    print_buildrequires: bool,
) -> Result<ResolveOutcome> {
    let cargo_home = make_cargo_home(registry_dir)?;
    let cargo_home_path = cargo_home.path().to_path_buf();

    let gctx = make_global_context(&cargo_home_path)?;
    let ws = Workspace::new(manifest, &gctx)
        .with_context(|| format!("failed to open workspace at {}", manifest.display()))?;

    ops::generate_lockfile(&ws).context("cargo resolve failed")?;
    let buildrequires = if print_buildrequires {
        let lockfile = ws.root().join("Cargo.lock");
        buildrequires_from_lockfile(&lockfile)?
    } else {
        Vec::new()
    };

    Ok(ResolveOutcome { buildrequires })
}

fn create_overlay_registry(
    registry_dir: &Path,
    plan_session: Option<&str>,
    plan_reset: bool,
    storage_mode: PlanSessionStorage,
) -> Result<OverlayRegistry> {
    if let Some(name) = plan_session {
        return create_session_overlay_registry(registry_dir, name, plan_reset, storage_mode);
    }

    let tempdir = tempfile::Builder::new()
        .prefix("takopack-overlay-registry-")
        .tempdir()
        .context("failed to create temporary overlay registry")?;
    let registry_path = tempdir.path().join("registry");
    let superseded_path = tempdir.path().join("superseded");
    let upper_path = tempdir.path().join("upper");
    let work_path = tempdir.path().join("work");
    let (resolved, stats, mounted_fuse_overlay) = initialize_registry_storage(
        registry_dir,
        &registry_path,
        &upper_path,
        &work_path,
        storage_mode,
    )?;

    println!(
        "plan session registry storage: {}",
        storage_method_label(resolved)
    );
    Ok(OverlayRegistry {
        registry_dir: registry_path,
        superseded_dir: superseded_path,
        _tempdir: Some(tempdir),
        unmount_on_drop: mounted_fuse_overlay,
        session_name: None,
        session_root: None,
        session_file: None,
        state: PlanSessionState::new(registry_dir),
        stats,
    })
}

fn create_session_overlay_registry(
    registry_dir: &Path,
    session_name: &str,
    plan_reset: bool,
    storage_mode: PlanSessionStorage,
) -> Result<OverlayRegistry> {
    validate_plan_session_name(session_name)?;
    let session_root = plan_session_root()?.join(session_name);
    let registry_path = session_root.join("registry");
    let superseded_path = session_root.join("superseded");
    let session_file = session_root.join("session.json");
    let upper_path = session_root.join("upper");
    let work_path = session_root.join("work");
    let mut stats = OverlayCopyStats::default();

    if plan_reset && session_root.exists() {
        unmount_session_registry_best_effort(&registry_path);
        fs::remove_dir_all(&session_root)
            .with_context(|| format!("failed to reset plan session {}", session_root.display()))?;
    }

    let state = if session_root.exists() {
        let mut state = load_plan_session_state(&session_file)?;
        if state.base_registry != registry_dir.display().to_string() {
            takopack_bail!(
                "plan session '{}' was created from {}, but current registry is {}; use --plan-reset to recreate it",
                session_name,
                state.base_registry,
                registry_dir.display()
            );
        }
        // If the existing session was fuse-overlay, ensure it is mounted.
        if state.registry_storage.as_deref() == Some("fuse-overlay") {
            if !is_mountpoint(&registry_path) {
                log::info!(
                    "fuse-overlay session '{}' is not mounted; remounting",
                    session_name
                );
                let upper = state
                    .overlay_upper
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| upper_path.clone());
                let work = state
                    .overlay_work
                    .as_deref()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| work_path.clone());
                mount_prepared_fuse_overlay(registry_dir, &upper, &work, &registry_path)
                    .with_context(|| {
                        format!(
                            "failed to remount fuse-overlay for plan session '{}'",
                            session_name
                        )
                    })?;
                if state.overlay_upper.is_none() || state.overlay_work.is_none() {
                    state.overlay_upper = Some(upper.display().to_string());
                    state.overlay_work = Some(work.display().to_string());
                    save_plan_session_state(&session_file, &state)?;
                }
            }
        }
        println!(
            "plan session registry storage: {} (reusing existing session)",
            state.registry_storage.as_deref().unwrap_or("unknown")
        );
        state
    } else {
        let (resolved, created_stats, _mounted_fuse_overlay) = match initialize_registry_storage(
            registry_dir,
            &registry_path,
            &upper_path,
            &work_path,
            storage_mode,
        ) {
            Ok(created) => created,
            Err(err) => {
                unmount_session_registry_best_effort(&registry_path);
                let _ = fs::remove_dir_all(&session_root);
                return Err(err).with_context(|| {
                    format!(
                        "failed to initialize plan session '{}' registry",
                        session_name
                    )
                });
            }
        };
        stats = created_stats;

        println!(
            "plan session registry storage: {}",
            storage_method_label(resolved)
        );
        let mut state = PlanSessionState::new(registry_dir);
        state.registry_storage = Some(storage_method_label(resolved).to_string());
        state.session_registry = Some(registry_path.display().to_string());
        if resolved == ResolvedStorageMethod::FuseOverlay {
            state.overlay_upper = Some(upper_path.display().to_string());
            state.overlay_work = Some(work_path.display().to_string());
        }
        save_plan_session_state(&session_file, &state)?;
        state
    };

    Ok(OverlayRegistry {
        registry_dir: registry_path,
        superseded_dir: superseded_path,
        _tempdir: None,
        unmount_on_drop: false,
        session_name: Some(session_name.to_string()),
        session_root: Some(session_root),
        session_file: Some(session_file),
        state,
        stats,
    })
}

fn initialize_registry_storage(
    source_dir: &Path,
    registry_path: &Path,
    upper_path: &Path,
    work_path: &Path,
    storage_mode: PlanSessionStorage,
) -> Result<(ResolvedStorageMethod, OverlayCopyStats, bool)> {
    let mut stats = OverlayCopyStats::default();

    match storage_mode {
        PlanSessionStorage::FuseOverlay => {
            mount_prepared_fuse_overlay(source_dir, upper_path, work_path, registry_path)?;
            Ok((ResolvedStorageMethod::FuseOverlay, stats, true))
        }
        PlanSessionStorage::Auto => {
            match mount_prepared_fuse_overlay(source_dir, upper_path, work_path, registry_path) {
                Ok(()) => Ok((ResolvedStorageMethod::FuseOverlay, stats, true)),
                Err(err) => {
                    log::info!(
                        "fuse-overlayfs unavailable or failed for {}; falling back to reflink/copy: {:#}",
                        registry_path.display(),
                        err
                    );
                    cleanup_failed_fuse_overlay_dirs(registry_path, upper_path, work_path)?;
                    let resolved = copy_registry_tree_with_reflink_fallback(
                        source_dir,
                        registry_path,
                        PlanSessionStorage::Auto,
                        &mut stats,
                    )?;
                    Ok((resolved, stats, false))
                }
            }
        }
        PlanSessionStorage::Reflink | PlanSessionStorage::Copy | PlanSessionStorage::Hardlink => {
            let resolved = copy_registry_tree_with_reflink_fallback(
                source_dir,
                registry_path,
                storage_mode,
                &mut stats,
            )?;
            Ok((resolved, stats, false))
        }
    }
}

fn copy_registry_tree_with_reflink_fallback(
    source_dir: &Path,
    registry_path: &Path,
    storage_mode: PlanSessionStorage,
    stats: &mut OverlayCopyStats,
) -> Result<ResolvedStorageMethod> {
    fs::create_dir_all(registry_path)
        .with_context(|| format!("failed to create {}", registry_path.display()))?;

    let resolved = resolve_storage_mode_without_fuse(storage_mode, source_dir, registry_path)?;
    match copy_registry_tree(source_dir, registry_path, resolved, stats) {
        Ok(()) => Ok(resolved),
        Err(err)
            if storage_mode == PlanSessionStorage::Auto
                && resolved == ResolvedStorageMethod::Reflink =>
        {
            log::info!(
                "reflink copy failed for {}; falling back to copy: {:#}",
                registry_path.display(),
                err
            );
            remove_dir_all_if_exists(registry_path)?;
            fs::create_dir_all(registry_path)
                .with_context(|| format!("failed to recreate {}", registry_path.display()))?;
            *stats = OverlayCopyStats::default();
            copy_registry_tree(
                source_dir,
                registry_path,
                ResolvedStorageMethod::Copy,
                stats,
            )?;
            Ok(ResolvedStorageMethod::Copy)
        }
        Err(err) => Err(err),
    }
}

fn mount_prepared_fuse_overlay(
    lowerdir: &Path,
    upperdir: &Path,
    workdir: &Path,
    merged: &Path,
) -> Result<()> {
    fs::create_dir_all(merged).with_context(|| format!("failed to create {}", merged.display()))?;
    fs::create_dir_all(upperdir)
        .with_context(|| format!("failed to create {}", upperdir.display()))?;
    fs::create_dir_all(workdir)
        .with_context(|| format!("failed to create {}", workdir.display()))?;
    mount_fuse_overlay(lowerdir, upperdir, workdir, merged)
}

fn cleanup_failed_fuse_overlay_dirs(
    registry_path: &Path,
    upper_path: &Path,
    work_path: &Path,
) -> Result<()> {
    unmount_session_registry_best_effort(registry_path);
    remove_dir_all_if_exists(registry_path)?;
    remove_dir_all_if_exists(upper_path)?;
    remove_dir_all_if_exists(work_path)?;
    Ok(())
}

fn remove_dir_all_if_exists(path: &Path) -> Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn plan_session_root() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine XDG_DATA_HOME / home directory for plan sessions")
    })?;
    Ok(data_dir.join("takopack").join("plan-sessions"))
}

fn run_plan_summary_only(session_name: &str) -> Result<i32> {
    validate_plan_session_name(session_name)?;
    let session_root = plan_session_root()?.join(session_name);
    let session_file = session_root.join("session.json");
    let state = load_plan_session_state(&session_file)?;
    print_plan_summary(
        &state,
        Some(session_name),
        Some(&session_root),
        state.last_result.as_deref().unwrap_or("unknown"),
        state.last_stop_reason.as_deref().unwrap_or("not recorded"),
        state.last_iterations.unwrap_or(0),
    );
    Ok(0)
}

fn finish_plan_run(
    overlay: &mut OverlayRegistry,
    result: &str,
    stop_reason: &str,
    iterations: usize,
) -> Result<()> {
    overlay.state.last_result = Some(result.to_string());
    overlay.state.last_stop_reason = Some(stop_reason.to_string());
    overlay.state.last_iterations = Some(iterations);
    if let Some(path) = overlay.session_file.clone() {
        save_plan_session_state(&path, &overlay.state)?;
    }
    print_plan_summary(
        &overlay.state,
        overlay.session_name.as_deref(),
        overlay.session_root.as_deref(),
        result,
        stop_reason,
        iterations,
    );
    Ok(())
}

fn validate_plan_session_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
    {
        takopack_bail!(
            "invalid plan session name '{}'; use ASCII letters, digits, '.', '_' or '-'",
            name
        );
    }
    Ok(())
}

fn load_plan_session_state(path: &Path) -> Result<PlanSessionState> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let state: PlanSessionState = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    if state.schema_version != 1 {
        takopack_bail!(
            "unsupported plan session schema_version {} in {}",
            state.schema_version,
            path.display()
        );
    }
    Ok(state)
}

fn save_plan_session_state(path: &Path, state: &PlanSessionState) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(state)?;
    fs::write(path, json.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn parse_plan_add(value: &str) -> Result<PlannedAdd> {
    let Some((crate_name, version)) = value.rsplit_once('@') else {
        takopack_bail!("invalid --plan-add '{}'; expected CRATE@VERSION", value);
    };
    if crate_name.is_empty() || version.is_empty() {
        takopack_bail!("invalid --plan-add '{}'; expected CRATE@VERSION", value);
    }
    let version = Version::parse(version)
        .with_context(|| format!("invalid version in --plan-add '{}'", value))?;
    Ok(PlannedAdd {
        crate_name: crate_name.to_string(),
        version,
    })
}

fn parse_plan_upgrade(value: &str) -> Result<PlannedUpgrade> {
    let Some((crate_name, version)) = value.rsplit_once('@') else {
        takopack_bail!("invalid --plan-upgrade '{}'; expected CRATE@VERSION", value);
    };
    if crate_name.is_empty() || version.is_empty() {
        takopack_bail!("invalid --plan-upgrade '{}'; expected CRATE@VERSION", value);
    }
    let version = Version::parse(version)
        .with_context(|| format!("invalid version in --plan-upgrade '{}'", value))?;
    Ok(PlannedUpgrade {
        crate_name: crate_name.to_string(),
        version,
    })
}

fn add_crate_to_overlay(
    overlay: &mut OverlayRegistry,
    crate_name: &str,
    version: &Version,
) -> Result<bool> {
    let registry_path = format!("{}-{}", crate_name, version);
    let existed = overlay.path().join(&registry_path).is_dir();
    materialize_crate_from_crates_io(crate_name, version, overlay.path()).with_context(|| {
        format!(
            "failed to materialize {} {} in overlay registry",
            crate_name, version
        )
    })?;

    if !existed {
        record_added_crate(overlay, crate_name, version)?;
        return Ok(true);
    }

    Ok(false)
}

fn record_added_crate(
    overlay: &mut OverlayRegistry,
    crate_name: &str,
    version: &Version,
) -> Result<()> {
    let names = rust_crate_output_names(crate_name, version);
    let version = version.to_string();
    if overlay
        .state
        .added_crates
        .iter()
        .any(|entry| entry.crate_name == crate_name && entry.version == version)
    {
        return Ok(());
    }

    overlay.state.added_crates.push(AddedCrateRecord {
        crate_name: crate_name.to_string(),
        version,
        rpm_name: names.directory,
    });
    overlay.state.added_crates.sort_by(|a, b| {
        a.crate_name
            .cmp(&b.crate_name)
            .then_with(|| a.version.cmp(&b.version))
    });

    if let Some(path) = overlay.session_file.clone() {
        save_plan_session_state(&path, &overlay.state)?;
    }

    Ok(())
}

fn apply_upgrade_to_overlay(
    overlay: &mut OverlayRegistry,
    crate_name: &str,
    to_version: &Version,
    requirement: &str,
    required_by: Option<&RequiredByPackage>,
) -> Result<bool> {
    let to_version_string = to_version.to_string();
    let already_recorded = overlay
        .state
        .upgraded_crates
        .iter()
        .any(|entry| entry.crate_name == crate_name && entry.to_version == to_version_string);
    let existing = existing_same_compat_providers(overlay.path(), crate_name, to_version);
    let old_existing: Vec<ExistingProvider> = existing
        .into_iter()
        .filter(|provider| provider.version != to_version_string)
        .collect();

    if old_existing.is_empty() && already_recorded {
        return Ok(false);
    }
    if old_existing.is_empty()
        && !overlay
            .path()
            .join(format!("{}-{}", crate_name, to_version))
            .is_dir()
    {
        takopack_bail!(
            "no same-compat provider found for {}; use --plan-add for new compat providers",
            crate_name
        );
    }

    materialize_crate_from_crates_io(crate_name, to_version, overlay.path()).with_context(
        || {
            format!(
                "failed to materialize upgrade candidate {} {} in overlay registry",
                crate_name, to_version
            )
        },
    )?;

    let mut changed = false;
    for provider in old_existing {
        let moved = supersede_provider_dir(overlay, crate_name, &provider.version)?;
        record_upgraded_crate(
            overlay,
            crate_name,
            &provider.version,
            to_version,
            &provider.provider_name,
            requirement,
            required_by,
        )?;
        changed = changed || moved;
    }

    Ok(changed)
}

fn supersede_provider_dir(
    overlay: &OverlayRegistry,
    crate_name: &str,
    version: &str,
) -> Result<bool> {
    let dir_name = format!("{}-{}", crate_name, version);
    let src = overlay.path().join(&dir_name);
    if !src.exists() {
        return Ok(false);
    }

    fs::create_dir_all(&overlay.superseded_dir)
        .with_context(|| format!("failed to create {}", overlay.superseded_dir.display()))?;
    let dest = overlay.superseded_dir.join(&dir_name);
    if dest.exists() {
        fs::remove_dir_all(&dest)
            .with_context(|| format!("failed to remove old superseded {}", dest.display()))?;
    }
    move_dir_or_copy_remove(&src, &dest).with_context(|| {
        format!(
            "failed to move superseded provider {} to {}",
            src.display(),
            dest.display()
        )
    })?;

    Ok(true)
}

const EXDEV_RAW_OS_ERROR: i32 = 18;

fn move_dir_or_copy_remove(src: &Path, dest: &Path) -> Result<()> {
    move_dir_or_copy_remove_with(src, dest, |src, dest| fs::rename(src, dest))
}

fn move_dir_or_copy_remove_with<F>(src: &Path, dest: &Path, rename_fn: F) -> Result<()>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    if dest.exists() {
        takopack_bail!("destination already exists: {}", dest.display());
    }

    match rename_fn(src, dest) {
        Ok(()) => Ok(()),
        Err(err) if is_cross_device_link(&err) => {
            log::debug!(
                "rename {} -> {} failed with EXDEV; copying then removing source",
                src.display(),
                dest.display()
            );
            copy_dir_recursively(src, dest)?;
            fs::remove_dir_all(src)
                .with_context(|| format!("failed to remove moved source {}", src.display()))?;
            Ok(())
        }
        Err(err) => Err(err)
            .with_context(|| format!("failed to rename {} to {}", src.display(), dest.display())),
    }
}

fn is_cross_device_link(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(EXDEV_RAW_OS_ERROR)
}

fn copy_dir_recursively(src: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        takopack_bail!("destination already exists: {}", dest.display());
    }
    let metadata =
        fs::metadata(src).with_context(|| format!("failed to inspect {}", src.display()))?;
    if !metadata.is_dir() {
        takopack_bail!("source is not a directory: {}", src.display());
    }

    fs::create_dir_all(dest).with_context(|| format!("failed to create {}", dest.display()))?;
    for entry in WalkDir::new(src) {
        let entry = entry.with_context(|| format!("failed to walk {}", src.display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(src)
            .with_context(|| format!("{} is not under {}", path.display(), src.display()))?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let out = dest.join(rel);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&out)
                .with_context(|| format!("failed to create {}", out.display()))?;
        } else if file_type.is_file() {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(path, &out).with_context(|| {
                format!("failed to copy {} to {}", path.display(), out.display())
            })?;
            let permissions = fs::metadata(path)
                .with_context(|| format!("failed to inspect {}", path.display()))?
                .permissions();
            fs::set_permissions(&out, permissions)
                .with_context(|| format!("failed to set permissions on {}", out.display()))?;
        } else if file_type.is_symlink() {
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to inspect symlink target {}", path.display()))?;
            if metadata.is_file() {
                fs::copy(path, &out).with_context(|| {
                    format!("failed to copy {} to {}", path.display(), out.display())
                })?;
            } else if metadata.is_dir() {
                fs::create_dir_all(&out)
                    .with_context(|| format!("failed to create {}", out.display()))?;
            }
        }
    }

    Ok(())
}

fn record_upgraded_crate(
    overlay: &mut OverlayRegistry,
    crate_name: &str,
    from_version: &str,
    to_version: &Version,
    rpm_name: &str,
    requirement: &str,
    required_by: Option<&RequiredByPackage>,
) -> Result<()> {
    let to_version = to_version.to_string();
    if overlay.state.upgraded_crates.iter().any(|entry| {
        entry.crate_name == crate_name
            && entry.from_version == from_version
            && entry.to_version == to_version
    }) {
        return Ok(());
    }

    overlay.state.upgraded_crates.push(UpgradedCrateRecord {
        crate_name: crate_name.to_string(),
        from_version: from_version.to_string(),
        to_version,
        rpm_name: rpm_name.to_string(),
        required_by: required_by.map(format_required_by).unwrap_or_default(),
        requirement: requirement.to_string(),
    });
    overlay.state.upgraded_crates.sort_by(|a, b| {
        a.crate_name
            .cmp(&b.crate_name)
            .then_with(|| a.from_version.cmp(&b.from_version))
            .then_with(|| a.to_version.cmp(&b.to_version))
    });

    if let Some(path) = overlay.session_file.clone() {
        save_plan_session_state(&path, &overlay.state)?;
    }

    Ok(())
}

/// Resolve storage modes that do not require creating a live overlay mount.
///
/// Actual `Auto` initialization is handled by `initialize_registry_storage`,
/// which first attempts a real fuse-overlayfs mount and falls back here only
/// when fuse-overlayfs is unavailable or the mount fails.
fn resolve_storage_mode_without_fuse(
    mode: PlanSessionStorage,
    source_dir: &Path,
    dest_dir: &Path,
) -> Result<ResolvedStorageMethod> {
    match mode {
        PlanSessionStorage::FuseOverlay => {
            takopack_bail!("internal error: fuse-overlay requested in non-fuse storage resolver");
        }
        PlanSessionStorage::Auto => {
            if probe_reflink_support(source_dir, dest_dir) {
                Ok(ResolvedStorageMethod::Reflink)
            } else {
                log::info!(
                    "reflink not supported between {} and {}; falling back to copy",
                    source_dir.display(),
                    dest_dir.display()
                );
                Ok(ResolvedStorageMethod::Copy)
            }
        }
        PlanSessionStorage::Reflink => Ok(ResolvedStorageMethod::Reflink),
        PlanSessionStorage::Copy => Ok(ResolvedStorageMethod::Copy),
        PlanSessionStorage::Hardlink => Ok(ResolvedStorageMethod::Hardlink),
    }
}

fn storage_method_label(method: ResolvedStorageMethod) -> &'static str {
    match method {
        ResolvedStorageMethod::FuseOverlay => "fuse-overlay",
        ResolvedStorageMethod::Reflink => "reflink",
        ResolvedStorageMethod::Copy => "copy",
        ResolvedStorageMethod::Hardlink => "hardlink",
    }
}

/// Check whether `fuse-overlayfs` command is available on the system.
fn probe_fuse_overlayfs() -> bool {
    use std::process::Command;
    Command::new("fuse-overlayfs")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Mount a fuse-overlayfs overlay.
///
/// `lowerdir`: the baseline registry (read-only layer).
/// `upperdir`: writable upper layer for copy-on-write.
/// `workdir`:  overlay internal work directory.
/// `merged`:   the merged mount point visible to the session.
fn mount_fuse_overlay(
    lowerdir: &Path,
    upperdir: &Path,
    workdir: &Path,
    merged: &Path,
) -> Result<()> {
    use std::process::Command;
    if !probe_fuse_overlayfs() {
        takopack_bail!(
            "fuse-overlayfs is not available; install fuse-overlayfs or use a different storage mode"
        );
    }
    let options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lowerdir.display(),
        upperdir.display(),
        workdir.display()
    );
    let output = Command::new("fuse-overlayfs")
        .arg("-o")
        .arg(&options)
        .arg(merged)
        .output()
        .context("failed to execute fuse-overlayfs")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("fuse-overlayfs mount failed: {}", stderr.trim());
    }
    Ok(())
}

/// Best-effort unmount of a FUSE mount point.
///
/// Tries fusermount3, fusermount, then umount.  Logs failures but does not
/// return an error, since this is used during cleanup where we want to
/// continue even if unmount fails.
fn unmount_session_registry_best_effort(path: &Path) {
    use std::process::Command;

    for cmd in &["fusermount3", "fusermount", "umount"] {
        let args: Vec<&str> = if *cmd == "umount" { vec![] } else { vec!["-u"] };
        let mut command = Command::new(cmd);
        for arg in &args {
            command.arg(arg);
        }
        command.arg(path);
        match command
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
        {
            Ok(status) if status.success() => {
                log::debug!("unmounted {} using {}", path.display(), cmd);
                return;
            }
            _ => continue,
        }
    }
    log::debug!(
        "best-effort unmount of {} failed with all methods; continuing",
        path.display()
    );
}

/// Check whether a path is a mount point by reading `/proc/self/mountinfo`.
fn is_mountpoint(path: &Path) -> bool {
    let Ok(canonical) = path.canonicalize() else {
        return false;
    };
    let canonical_str = canonical.display().to_string();
    let Ok(mountinfo) = fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    // Each line in mountinfo has fields separated by spaces.
    // Field 5 (0-indexed: 4) is the mount point.
    for line in mountinfo.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 && fields[4] == canonical_str {
            return true;
        }
    }
    false
}

/// Try to create a reflink copy of a small probe file to detect CoW support.
fn probe_reflink_support(source_dir: &Path, dest_dir: &Path) -> bool {
    use std::process::Command;

    // Find any regular file in source_dir to use as a probe.
    let probe_src = WalkDir::new(source_dir)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
        .find(|e| e.file_type().is_file());
    let Some(probe_src) = probe_src else {
        // Empty registry — reflink is fine (nothing to copy).
        return true;
    };

    let probe_dest = dest_dir.join(".takopack-reflink-probe");
    let result = Command::new("cp")
        .args(["--reflink=always", "--"])
        .arg(probe_src.path())
        .arg(&probe_dest)
        .output();

    let _ = fs::remove_file(&probe_dest);

    match result {
        Ok(output) => output.status.success(),
        Err(_) => false,
    }
}

/// Copy the registry tree from `source_dir` to `dest_dir` using the
/// specified storage method.
///
/// For `Auto` mode callers: if the initial attempt with `Reflink` fails,
/// the caller should remove the partially-created dest and retry with `Copy`.
/// However, `resolve_storage_mode` already probes, so this is a safety net.
fn copy_registry_tree(
    source_dir: &Path,
    dest_dir: &Path,
    method: ResolvedStorageMethod,
    stats: &mut OverlayCopyStats,
) -> Result<()> {
    for entry in WalkDir::new(source_dir)
        .into_iter()
        .filter_entry(|entry| should_copy_registry_entry(entry.path(), source_dir))
    {
        let entry = entry.context("failed to walk source registry for overlay")?;
        let path = entry.path();
        let rel = path
            .strip_prefix(source_dir)
            .with_context(|| format!("{} is not under {}", path.display(), source_dir.display()))?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = dest_dir.join(rel);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&dest)
                .with_context(|| format!("failed to create {}", dest.display()))?;
        } else if file_type.is_file() {
            copy_file_with_mode(path, &dest, method, stats)?;
        } else if file_type.is_symlink() {
            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to inspect symlink target {}", path.display()))?;
            if metadata.is_file() {
                copy_file_with_mode(path, &dest, method, stats)?;
            } else if metadata.is_dir() {
                fs::create_dir_all(&dest)
                    .with_context(|| format!("failed to create {}", dest.display()))?;
            }
        }
    }

    Ok(())
}

fn should_copy_registry_entry(path: &Path, source_dir: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(source_dir) else {
        return true;
    };
    if rel.as_os_str().is_empty() {
        return true;
    }

    for component in rel.components() {
        let std::path::Component::Normal(part) = component else {
            continue;
        };
        if part == "target" {
            return false;
        }
    }

    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return true;
    };
    !name.starts_with(".takopack-sync-") && !name.starts_with(".takopack-plan-")
}

/// Copy a single file using the specified method.
fn copy_file_with_mode(
    src: &Path,
    dest: &Path,
    method: ResolvedStorageMethod,
    stats: &mut OverlayCopyStats,
) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    match method {
        ResolvedStorageMethod::FuseOverlay => {
            takopack_bail!("internal error: fuse-overlay storage cannot be used for file copies");
        }
        ResolvedStorageMethod::Hardlink => match fs::hard_link(src, dest) {
            Ok(()) => {
                stats.hardlinked_files += 1;
                Ok(())
            }
            Err(err) => {
                log::debug!(
                    "hardlink {} -> {} failed: {}; falling back to copy",
                    src.display(),
                    dest.display(),
                    err
                );
                fs::copy(src, dest).with_context(|| {
                    format!("failed to copy {} to {}", src.display(), dest.display())
                })?;
                stats.copied_files += 1;
                Ok(())
            }
        },
        ResolvedStorageMethod::Reflink => {
            reflink_copy_file(src, dest).with_context(|| {
                format!(
                    "reflink copy {} -> {} failed",
                    src.display(),
                    dest.display()
                )
            })?;
            stats.reflinked_files += 1;
            Ok(())
        }
        ResolvedStorageMethod::Copy => {
            fs::copy(src, dest).with_context(|| {
                format!("failed to copy {} to {}", src.display(), dest.display())
            })?;
            stats.copied_files += 1;
            Ok(())
        }
    }
}

/// Perform a reflink (CoW) copy of a single file using `cp --reflink=always`.
fn reflink_copy_file(src: &Path, dest: &Path) -> Result<()> {
    use std::process::Command;
    let output = Command::new("cp")
        .args(["--reflink=always", "--preserve=mode,timestamps", "--"])
        .arg(src)
        .arg(dest)
        .output()
        .with_context(|| format!("failed to execute cp for reflink copy of {}", src.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "cp --reflink=always failed for {} -> {}: {}",
            src.display(),
            dest.display(),
            stderr.trim()
        );
    }
    Ok(())
}

fn plan_and_materialize_missing_crate(
    missing: &MissingPackageError,
    root_manifest: &Path,
    overlay: &mut OverlayRegistry,
    no_dev: bool,
) -> Result<PlanActionResult> {
    let required_by = missing.required_by.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "missing {}, but failed to identify the package that requires it",
            missing.crate_name
        )
    })?;
    let parent_manifest = locate_parent_manifest(&required_by, root_manifest, overlay.path())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing {}, but failed to locate parent manifest for {} {}",
                missing.crate_name,
                required_by.name,
                required_by.version
            )
        })?;
    let requirement = infer_dependency_requirement(&parent_manifest, &missing.crate_name, !no_dev)?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing {}, but failed to infer version requirement from {}",
                missing.crate_name,
                parent_manifest.display()
            )
        })?;
    let selected_version = resolve_crates_io_version_req(&missing.crate_name, &requirement)
        .with_context(|| {
            format!(
                "failed to select crates.io version for {} {}",
                missing.crate_name, requirement
            )
        })?;
    let required_by_key = format_required_by(&required_by);
    let key = format!(
        "missing:{}:{}:{}:{}",
        missing.crate_name, requirement, selected_version, required_by_key
    );
    let changed = add_crate_to_overlay(overlay, &missing.crate_name, &selected_version)?;
    Ok(PlanActionResult {
        key,
        changed,
        last_action: format!("add {} {}", missing.crate_name, selected_version),
    })
}

fn print_plan_summary(
    state: &PlanSessionState,
    session_name: Option<&str>,
    session_root: Option<&Path>,
    result: &str,
    stop_reason: &str,
    iterations: usize,
) {
    println!("Plan summary");
    println!("  session: {}", session_name.unwrap_or("(temporary)"));
    println!(
        "  session path: {}",
        session_root
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "(temporary)".to_string())
    );
    println!("  result: {}", result);
    println!("  iterations: {}", iterations);
    println!();

    println!("New provider candidates: {}", state.added_crates.len());
    if state.added_crates.is_empty() {
        println!("  (none)");
    } else {
        for added in &state.added_crates {
            println!(
                "  {} {} -> {}",
                added.crate_name, added.version, added.rpm_name
            );
            println!(
                "    command: takopack cargo pkg {} {} --directory /tmp/providers/{}",
                added.crate_name, added.version, added.rpm_name
            );
        }
    }

    println!();
    println!("Upgrade candidates: {}", state.upgraded_crates.len());
    if state.upgraded_crates.is_empty() {
        println!("  (none)");
    } else {
        for upgraded in &state.upgraded_crates {
            println!(
                "  {} {} -> {} -> {}",
                upgraded.crate_name, upgraded.from_version, upgraded.to_version, upgraded.rpm_name
            );
            println!(
                "    command: takopack cargo pkg {} {} --directory /tmp/providers/{}",
                upgraded.crate_name, upgraded.to_version, upgraded.rpm_name
            );
            if !upgraded.requirement.is_empty() {
                println!("    required: {}", upgraded.requirement);
            }
            if !upgraded.required_by.is_empty() {
                println!("    required by: {}", upgraded.required_by);
            }
        }
    }

    println!();
    println!("Stop reason:");
    println!("  {}", stop_reason);
}

fn print_upgrade_candidates(candidates: &[UpgradeCandidate]) {
    println!("Upgrade candidates:");
    for candidate in candidates {
        println!("  {}", candidate.crate_name);
        for existing in &candidate.existing {
            println!(
                "    existing: {} {}",
                existing.provider_name, existing.version
            );
        }
        println!("    required: {}", candidate.requirement);
        if let Some(required_by) = &candidate.required_by {
            println!("    required by: {}", format_required_by(required_by));
        }
        println!("    candidate: {}", candidate.candidate_version);
        println!(
            "    candidate provider: {}",
            candidate.candidate_provider_name
        );
        println!("    action: upgrade existing provider");
    }
}

fn print_continue_with_upgrade_command(
    manifest: &Path,
    no_dev: bool,
    print_buildrequires: bool,
    plan_session: Option<&str>,
    candidate: &UpgradeCandidate,
) {
    println!("Continue with:");
    let mut parts = vec![
        "takopack".to_string(),
        "cargo".to_string(),
        "resolve-check".to_string(),
        shell_quote(&manifest.display().to_string()),
    ];
    if no_dev {
        parts.push("--no-dev".to_string());
    }
    parts.push("--plan-missing".to_string());
    if let Some(session) = plan_session {
        parts.push("--plan-session".to_string());
        parts.push(shell_quote(session));
    }
    if print_buildrequires {
        parts.push("--print-buildrequires".to_string());
    }
    parts.push("--plan-upgrade".to_string());
    parts.push(format!(
        "{}@{}",
        candidate.crate_name, candidate.candidate_version
    ));
    println!("  {}", parts.join(" "));
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '_' | '-' | '+' | '='))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn detect_no_progress(
    action_keys: &mut HashSet<String>,
    action: &PlanActionResult,
) -> Option<String> {
    if !action.changed {
        return Some(format!("no progress detected for {}", action.key));
    }
    if !action_keys.insert(action.key.clone()) {
        return Some(format!("no progress detected for repeated {}", action.key));
    }
    None
}

fn print_plan_progress_if_needed(
    iterations: usize,
    progress_interval: usize,
    state: &PlanSessionState,
    last_action: &str,
) {
    if progress_interval == 0 || iterations % progress_interval != 0 {
        return;
    }

    println!("Planning progress:");
    println!("  iterations: {}", iterations);
    println!("  new providers: {}", state.added_crates.len());
    println!("  upgrades: {}", state.upgraded_crates.len());
    println!("  last action: {}", last_action);
    println!();
}

fn parse_missing_package_error(error_text: &str) -> Option<MissingPackageError> {
    let crate_name = Regex::new(r#"no matching package named `([^`]+)` found"#)
        .ok()
        .and_then(|regex| {
            regex
                .captures(error_text)
                .and_then(|captures| captures.get(1))
                .map(|capture| capture.as_str().to_string())
        })
        .or_else(|| {
            Regex::new(r#"searched package name:\s*`([^`]+)`"#)
                .ok()
                .and_then(|regex| {
                    regex
                        .captures(error_text)
                        .and_then(|captures| captures.get(1))
                        .map(|capture| capture.as_str().to_string())
                })
        })?;

    let required_by_re = Regex::new(r#"required by package `([^`]+)`"#).ok()?;
    let required_by = required_by_re
        .captures(error_text)
        .and_then(|captures| captures.get(1))
        .and_then(|package| parse_required_by_package(package.as_str()));

    Some(MissingPackageError {
        crate_name,
        required_by,
    })
}

fn parse_required_by_package(package: &str) -> Option<RequiredByPackage> {
    let package_re = Regex::new(r#"^(.+) v([^ ]+)(?: \((.*)\))?$"#).ok()?;
    let captures = package_re.captures(package)?;
    let path = captures.get(3).map(|path| PathBuf::from(path.as_str()));
    Some(RequiredByPackage {
        name: captures.get(1)?.as_str().to_string(),
        version: captures.get(2)?.as_str().to_string(),
        path,
    })
}

fn format_required_by(required_by: &RequiredByPackage) -> String {
    let version = Version::parse(&required_by.version)
        .map(|version| clean_semver_without_build(&version))
        .unwrap_or_else(|_| required_by.version.clone());
    format!("{} {}", required_by.name, version)
}

fn clean_semver_without_build(version: &Version) -> String {
    format!(
        "{}.{}.{}{}",
        version.major,
        version.minor,
        version.patch,
        if version.pre.is_empty() {
            String::new()
        } else {
            format!("-{}", version.pre)
        }
    )
}

fn parse_version_selection_failure(error_text: &str) -> Option<VersionSelectionFailure> {
    if !error_text.contains("failed to select a version for the requirement")
        && !error_text.contains("candidate versions found which didn't match")
    {
        return None;
    }

    let req_re = Regex::new(r#"failed to select a version for the requirement `([^`]+)`"#).ok()?;
    let req_line = req_re
        .captures(error_text)
        .and_then(|captures| captures.get(1))
        .map(|capture| capture.as_str())?;
    let crate_name = parse_requirement_crate_name(req_line)?;
    let requirement = parse_requirement_text(req_line).unwrap_or_else(|| req_line.to_string());
    let required_by_re = Regex::new(r#"required by package `([^`]+)`"#).ok()?;
    let required_by = required_by_re
        .captures(error_text)
        .and_then(|captures| captures.get(1))
        .and_then(|package| parse_required_by_package(package.as_str()));
    Some(VersionSelectionFailure {
        crate_name,
        requirement,
        required_by,
    })
}

fn plan_or_conflict_version_selection_failure(
    failure: &VersionSelectionFailure,
    overlay: &mut OverlayRegistry,
    allow_session_upgrades: bool,
) -> Result<VersionSelectionPlan> {
    let selected_version = resolve_crates_io_version_req(&failure.crate_name, &failure.requirement)
        .with_context(|| {
            format!(
                "failed to select crates.io version for {} {}",
                failure.crate_name, failure.requirement
            )
        })?;
    let same_compat =
        existing_same_compat_providers(overlay.path(), &failure.crate_name, &selected_version);
    let selected_version_string = selected_version.to_string();
    let old_same_compat: Vec<ExistingProvider> = same_compat
        .iter()
        .filter(|provider| provider.version != selected_version_string)
        .cloned()
        .collect();

    if !old_same_compat.is_empty() {
        let candidate_provider_name =
            rust_crate_output_names(&failure.crate_name, &selected_version).directory;
        let candidate = UpgradeCandidate {
            crate_name: failure.crate_name.clone(),
            requirement: failure.requirement.clone(),
            required_by: failure.required_by.clone(),
            candidate_version: selected_version,
            candidate_provider_name,
            existing: old_same_compat,
        };
        if allow_session_upgrades {
            let from_versions = candidate
                .existing
                .iter()
                .map(|provider| provider.version.clone())
                .collect::<Vec<_>>()
                .join(",");
            let key = format!(
                "upgrade:{}:{}:{}:{}",
                candidate.crate_name,
                from_versions,
                candidate.candidate_version,
                candidate
                    .required_by
                    .as_ref()
                    .map(format_required_by)
                    .unwrap_or_default()
            );
            let changed = apply_upgrade_candidate_to_overlay(overlay, &candidate)?;
            return Ok(VersionSelectionPlan::Continue(PlanActionResult {
                key,
                changed,
                last_action: format!(
                    "upgrade {} {} -> {}",
                    candidate.crate_name, from_versions, candidate.candidate_version
                ),
            }));
        }
        return Ok(VersionSelectionPlan::Stopped(candidate));
    }

    if !same_compat.is_empty() {
        takopack_bail!(
            "{} {} is already present in the overlay, but Cargo still reports it does not satisfy {}; this may be a feature or policy conflict",
            failure.crate_name,
            selected_version_string,
            failure.requirement
        );
    }

    let key = format!(
        "missing-compat:{}:{}:{}:{}",
        failure.crate_name,
        failure.requirement,
        selected_version,
        failure
            .required_by
            .as_ref()
            .map(format_required_by)
            .unwrap_or_default()
    );
    let changed = add_crate_to_overlay(overlay, &failure.crate_name, &selected_version)?;
    Ok(VersionSelectionPlan::Continue(PlanActionResult {
        key,
        changed,
        last_action: format!("add {} {}", failure.crate_name, selected_version),
    }))
}

fn apply_upgrade_candidate_to_overlay(
    overlay: &mut OverlayRegistry,
    candidate: &UpgradeCandidate,
) -> Result<bool> {
    apply_upgrade_to_overlay(
        overlay,
        &candidate.crate_name,
        &candidate.candidate_version,
        &candidate.requirement,
        candidate.required_by.as_ref(),
    )
}

fn existing_same_compat_providers(
    registry_dir: &Path,
    crate_name: &str,
    selected_version: &Version,
) -> Vec<ExistingProvider> {
    let wanted_compat = calculate_compat_version(selected_version);
    existing_providers_for_crate(registry_dir, crate_name)
        .into_iter()
        .filter(|provider| provider.compat == wanted_compat)
        .collect()
}

fn parse_requirement_crate_name(req_line: &str) -> Option<String> {
    let name_re = Regex::new(r#"^\s*([A-Za-z0-9_-]+)\s*(?:=|\s|$)"#).ok()?;
    Some(name_re.captures(req_line)?.get(1)?.as_str().to_string())
}

fn parse_requirement_text(req_line: &str) -> Option<String> {
    let (_, requirement) = req_line.split_once('=')?;
    let requirement = requirement.trim().trim_matches('"').to_string();
    if requirement.is_empty() {
        None
    } else {
        Some(requirement)
    }
}

fn locate_parent_manifest(
    parent: &RequiredByPackage,
    root_manifest: &Path,
    overlay_registry: &Path,
) -> Option<PathBuf> {
    if let Some(path) = &parent.path {
        let direct = if path.file_name().is_some_and(|name| name == "Cargo.toml") {
            path.clone()
        } else {
            path.join("Cargo.toml")
        };
        if direct.is_file() {
            return Some(direct);
        }
    }

    if manifest_matches_package(root_manifest, &parent.name, &parent.version) {
        return Some(root_manifest.to_path_buf());
    }

    let exact = overlay_registry
        .join(format!("{}-{}", parent.name, parent.version))
        .join("Cargo.toml");
    if exact.is_file() {
        return Some(exact);
    }

    let entries = fs::read_dir(overlay_registry).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        if manifest_matches_package(&manifest, &parent.name, &parent.version) {
            return Some(manifest);
        }
    }

    None
}

fn manifest_matches_package(manifest: &Path, name: &str, version: &str) -> bool {
    read_manifest_package_name_version(manifest).is_some_and(|(manifest_name, manifest_version)| {
        manifest_name == name && manifest_version == version
    })
}

fn read_manifest_package_name_version(manifest: &Path) -> Option<(String, String)> {
    let content = fs::read_to_string(manifest).ok()?;
    let doc: toml::Value = toml::from_str(&content).ok()?;
    let package = doc.get("package")?.as_table()?;
    let name = package.get("name")?.as_str()?.to_string();
    let version = package.get("version")?.as_str()?.to_string();
    Some((name, version))
}

fn existing_providers_for_crate(registry_dir: &Path, crate_name: &str) -> Vec<ExistingProvider> {
    let mut providers = Vec::new();
    let Ok(entries) = fs::read_dir(registry_dir) else {
        return providers;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let manifest = path.join("Cargo.toml");
        let Some((name, version)) = read_manifest_package_name_version(&manifest) else {
            continue;
        };
        if name != crate_name {
            continue;
        }
        let (provider_name, compat) = Version::parse(&version)
            .map(|version| {
                let names = rust_crate_output_names(crate_name, &version);
                let compat = calculate_compat_version(&version);
                (names.directory, compat)
            })
            .unwrap_or_else(|_| {
                (
                    format!("rust-{}-{}", crate_name.replace('_', "-"), version),
                    version.clone(),
                )
            });
        providers.push(ExistingProvider {
            provider_name,
            version,
            compat,
        });
    }

    providers.sort_by(|a, b| a.version.cmp(&b.version));
    providers
}

fn infer_dependency_requirement(
    parent_manifest: &Path,
    missing_crate: &str,
    include_dev: bool,
) -> Result<Option<String>> {
    let content = fs::read_to_string(parent_manifest)
        .with_context(|| format!("failed to read {}", parent_manifest.display()))?;
    let doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", parent_manifest.display()))?;
    let Some(root) = doc.as_table() else {
        return Ok(None);
    };

    for section in ["dependencies", "build-dependencies"] {
        if let Some(requirement) =
            dependency_requirement_from_section(root, &doc, section, missing_crate)
        {
            return Ok(Some(requirement));
        }
    }
    if include_dev {
        if let Some(requirement) =
            dependency_requirement_from_section(root, &doc, "dev-dependencies", missing_crate)
        {
            return Ok(Some(requirement));
        }
    }

    if let Some(targets) = root.get("target").and_then(|target| target.as_table()) {
        for target in targets.values() {
            let Some(target) = target.as_table() else {
                continue;
            };
            for section in ["dependencies", "build-dependencies"] {
                if let Some(requirement) =
                    dependency_requirement_from_section(target, &doc, section, missing_crate)
                {
                    return Ok(Some(requirement));
                }
            }
            if include_dev {
                if let Some(requirement) = dependency_requirement_from_section(
                    target,
                    &doc,
                    "dev-dependencies",
                    missing_crate,
                ) {
                    return Ok(Some(requirement));
                }
            }
        }
    }

    Ok(None)
}

fn dependency_requirement_from_section(
    table: &toml::map::Map<String, toml::Value>,
    root_doc: &toml::Value,
    section: &str,
    missing_crate: &str,
) -> Option<String> {
    let deps = table.get(section)?.as_table()?;
    for (alias, dep_value) in deps {
        if let Some(requirement) =
            dependency_requirement_from_value(alias, dep_value, root_doc, missing_crate)
        {
            return Some(requirement);
        }
    }

    None
}

fn dependency_requirement_from_value(
    alias: &str,
    dep_value: &toml::Value,
    root_doc: &toml::Value,
    missing_crate: &str,
) -> Option<String> {
    match dep_value {
        toml::Value::String(requirement) if alias == missing_crate => Some(requirement.clone()),
        toml::Value::Table(dep_table) => {
            let package_name = dep_table
                .get("package")
                .and_then(|value| value.as_str())
                .unwrap_or(alias);
            if package_name != missing_crate {
                return None;
            }

            if dep_table
                .get("workspace")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                return workspace_dependency_requirement(root_doc, package_name);
            }

            dep_table
                .get("version")
                .and_then(|value| value.as_str())
                .map(|version| version.to_string())
                .or_else(|| Some("*".to_string()))
        }
        _ => None,
    }
}

fn workspace_dependency_requirement(root_doc: &toml::Value, crate_name: &str) -> Option<String> {
    let deps = root_doc.get("workspace")?.get("dependencies")?.as_table()?;
    for (alias, dep_value) in deps {
        if let Some(requirement) =
            dependency_requirement_from_value(alias, dep_value, root_doc, crate_name)
        {
            return Some(requirement);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Manifest / path resolution
// ---------------------------------------------------------------------------

fn resolve_manifest(path: &Path) -> Result<(PathBuf, PathBuf)> {
    if path.is_dir() {
        let manifest = path.join("Cargo.toml");
        if !manifest.is_file() {
            takopack_bail!("no Cargo.toml found in directory: {}", path.display());
        }
        Ok((manifest, path.to_path_buf()))
    } else if path.is_file() {
        let workdir = path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        Ok((path.to_path_buf(), workdir))
    } else {
        takopack_bail!("path does not exist: {}", path.display());
    }
}

// ---------------------------------------------------------------------------
// Manifest target parsing
// ---------------------------------------------------------------------------

/// Parsed target information from a `Cargo.toml`.
#[derive(Debug, Clone)]
struct ManifestTargets {
    /// `true` if the manifest contains `[workspace]`.
    has_workspace: bool,
    /// Library target path (explicit `[lib].path` or default `src/lib.rs`).
    /// `None` if no `[lib]` section and we should fall through to defaults.
    lib_path: Option<PathBuf>,
    /// Whether a `[lib]` section exists at all.
    has_lib_section: bool,
    /// Binary target paths.  Each entry is the path from `[[bin]].path`,
    /// or a Cargo-default path derived from `[[bin]].name`.
    bin_paths: Vec<PathBuf>,
    /// Whether any `[[bin]]` sections exist.
    has_bin_sections: bool,
}

/// Parse `Cargo.toml` to extract target declarations without loading the
/// full Cargo machinery.  We use the `toml` crate to read the relevant
/// sections.
fn parse_manifest_targets(manifest: &Path) -> Result<ManifestTargets> {
    let content = fs::read_to_string(manifest)
        .with_context(|| format!("failed to read {}", manifest.display()))?;
    let doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", manifest.display()))?;
    let table = doc.as_table();

    let has_workspace = table
        .and_then(|t| t.get("workspace"))
        .and_then(|v| v.as_table())
        .is_some();

    // [lib]
    let lib_section = table.and_then(|t| t.get("lib")).and_then(|v| v.as_table());
    let has_lib_section = lib_section.is_some();
    let lib_path = if let Some(lib) = lib_section {
        if let Some(p) = lib.get("path").and_then(|v| v.as_str()) {
            Some(PathBuf::from(p))
        } else {
            // [lib] exists but no path → default is src/lib.rs
            Some(PathBuf::from("src/lib.rs"))
        }
    } else {
        None
    };

    // [[bin]]
    let bin_array = table.and_then(|t| t.get("bin")).and_then(|v| v.as_array());
    let has_bin_sections = bin_array.is_some();
    let mut bin_paths = Vec::new();
    if let Some(bins) = bin_array {
        for bin in bins {
            if let Some(bin_table) = bin.as_table() {
                if let Some(p) = bin_table.get("path").and_then(|v| v.as_str()) {
                    bin_paths.push(PathBuf::from(p));
                } else if let Some(name) = bin_table.get("name").and_then(|v| v.as_str()) {
                    // Cargo default: src/bin/<name>.rs
                    bin_paths.push(PathBuf::from(format!("src/bin/{}.rs", name)));
                }
            }
        }
    }

    Ok(ManifestTargets {
        has_workspace,
        lib_path,
        has_lib_section,
        bin_paths,
        has_bin_sections,
    })
}

// ---------------------------------------------------------------------------
// Mode detection
// ---------------------------------------------------------------------------

/// Determine whether the manifest directory is a real Cargo project
/// (real mode) or a bare `Cargo.toml` that needs scaffolding (virtual mode).
///
/// Rules:
/// 1. `[workspace]` → always real mode.
/// 2. `[lib]` with path → check if the file exists in workdir.
/// 3. `[[bin]]` with paths → check if at least one file exists.
/// 4. No explicit targets → check default paths (`src/lib.rs`,
///    `src/main.rs`, `src/bin/*.rs`).
/// 5. Otherwise → virtual mode.
fn detect_real_mode(targets: &ManifestTargets, workdir: &Path) -> bool {
    // 1. Workspace is always real.
    if targets.has_workspace {
        return true;
    }

    let has_explicit_targets = targets.has_lib_section || targets.has_bin_sections;

    if has_explicit_targets {
        // 2. Check declared lib target.
        if let Some(ref lib_path) = targets.lib_path {
            if workdir.join(lib_path).exists() {
                return true;
            }
        }

        // 3. Check declared bin targets – at least one must exist.
        for bin_path in &targets.bin_paths {
            if workdir.join(bin_path).exists() {
                return true;
            }
        }

        // Explicit targets declared, but none of the files exist → virtual.
        return false;
    }

    // 4. No explicit targets: check Cargo defaults.
    if workdir.join("src/lib.rs").exists() || workdir.join("src/main.rs").exists() {
        return true;
    }
    if let Ok(entries) = fs::read_dir(workdir.join("src/bin")) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|ext| ext == "rs") {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Registry directory resolution
// ---------------------------------------------------------------------------

fn resolve_registry_dir() -> Result<PathBuf> {
    // Try takopack.toml first.
    if let Some((config_path, config)) = load_takopack_toml()? {
        if let Some(registry) = config.registry {
            if let Some(local_path) = registry.local_path {
                let path = if local_path.is_absolute() {
                    local_path
                } else {
                    config_path
                        .parent()
                        .unwrap_or_else(|| Path::new("."))
                        .join(local_path)
                };
                return Ok(path);
            }
        }
    }

    // Fall back to the same default as registry-sync.
    default_registry_dir()
}

/// `$XDG_DATA_HOME/takopack/cargo-registry` or
/// `~/.local/share/takopack/cargo-registry`.
fn default_registry_dir() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine XDG_DATA_HOME / home directory for default registry path")
    })?;
    Ok(data_dir.join("takopack").join("cargo-registry"))
}

// ---------------------------------------------------------------------------
// Cargo API resolve – real mode
// ---------------------------------------------------------------------------

/// Resolve dependencies using the Cargo API, operating on the original
/// project directory.  A temporary `CARGO_HOME` is created so that we
/// can inject the local-registry source replacement without touching
/// the project's own `.cargo/config.toml`.
fn cargo_resolve(
    manifest: &Path,
    workdir: &Path,
    registry_dir: &Path,
    no_dev: bool,
    print_buildrequires: bool,
) -> Result<ResolveOutcome> {
    let _tmp_project;
    let manifest = if no_dev {
        let (tmp_project, tmp_manifest) = make_no_dev_real_project(manifest, workdir)?;
        _tmp_project = Some(tmp_project);
        tmp_manifest
    } else {
        _tmp_project = None;
        manifest
            .canonicalize()
            .with_context(|| format!("failed to canonicalize {}", manifest.display()))?
    };

    let cargo_home = make_cargo_home(registry_dir)?;
    let cargo_home_path = cargo_home.path().to_path_buf();

    let gctx = make_global_context(&cargo_home_path)?;
    let ws = Workspace::new(&manifest, &gctx)
        .with_context(|| format!("failed to open workspace at {}", manifest.display()))?;

    ops::generate_lockfile(&ws).context("cargo resolve failed")?;
    let buildrequires = if print_buildrequires {
        let lockfile = ws.root().join("Cargo.lock");
        buildrequires_from_lockfile(&lockfile)?
    } else {
        Vec::new()
    };

    Ok(ResolveOutcome { buildrequires })
}

// ---------------------------------------------------------------------------
// Cargo API resolve – virtual mode
// ---------------------------------------------------------------------------

/// Create a temporary project directory with stub target files derived
/// from the manifest's declared targets, copy `Cargo.toml` there, and
/// resolve.
fn cargo_resolve_virtual_with_options(
    manifest: &Path,
    registry_dir: &Path,
    targets: &ManifestTargets,
    no_dev: bool,
    print_buildrequires: bool,
) -> Result<ResolveOutcome> {
    let tmp = tempfile::tempdir().context("failed to create temporary directory")?;
    let tmp_path = tmp.path();

    // Copy Cargo.toml
    let tmp_manifest = tmp_path.join("Cargo.toml");
    fs::copy(manifest, &tmp_manifest)
        .with_context(|| format!("failed to copy {} to tempdir", manifest.display()))?;
    if no_dev {
        strip_dev_dependencies_from_manifest(&tmp_manifest)?;
    }

    // Create stub target files based on manifest declarations.
    create_virtual_stubs(tmp_path, targets)?;

    let tmp_manifest = tmp_manifest
        .canonicalize()
        .context("failed to canonicalize temp manifest")?;

    let cargo_home = make_cargo_home(registry_dir)?;
    let cargo_home_path = cargo_home.path().to_path_buf();

    let gctx = make_global_context(&cargo_home_path)?;
    let ws = Workspace::new(&tmp_manifest, &gctx)
        .with_context(|| format!("failed to open workspace at {}", tmp_manifest.display()))?;

    ops::generate_lockfile(&ws).context("cargo resolve failed")?;
    let buildrequires = if print_buildrequires {
        let lockfile = ws.root().join("Cargo.lock");
        buildrequires_from_lockfile(&lockfile)?
    } else {
        Vec::new()
    };

    Ok(ResolveOutcome { buildrequires })
}

/// Create stub source files in `project_dir` so that Cargo finds all
/// declared targets.
fn create_virtual_stubs(project_dir: &Path, targets: &ManifestTargets) -> Result<()> {
    let stub_content = "";
    let mut created_any = false;

    // Lib target
    if let Some(ref lib_path) = targets.lib_path {
        let full = project_dir.join(lib_path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&full, stub_content)?;
        log::debug!("virtual stub: {}", lib_path.display());
        created_any = true;
    }

    // Bin targets
    for bin_path in &targets.bin_paths {
        let full = project_dir.join(bin_path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent)?;
        }
        // Bin targets need fn main()
        fs::write(&full, "fn main() {}\n")?;
        log::debug!("virtual stub: {}", bin_path.display());
        created_any = true;
    }

    // If no targets were declared at all, create a default src/lib.rs
    if !created_any {
        let src = project_dir.join("src");
        fs::create_dir_all(&src)?;
        fs::write(src.join("lib.rs"), stub_content)?;
        log::debug!("virtual stub: src/lib.rs (default)");
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// no-dev manifest view
// ---------------------------------------------------------------------------

fn make_no_dev_real_project(
    manifest: &Path,
    workdir: &Path,
) -> Result<(tempfile::TempDir, PathBuf)> {
    let workdir = workdir
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", workdir.display()))?;
    let manifest = manifest
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", manifest.display()))?;
    let manifest_rel = manifest
        .strip_prefix(&workdir)
        .with_context(|| format!("{} is not under {}", manifest.display(), workdir.display()))?
        .to_path_buf();

    let tmp = tempfile::tempdir().context("failed to create no-dev temporary project")?;
    copy_project_tree_for_resolve(&workdir, tmp.path())?;

    let tmp_manifest = tmp.path().join(manifest_rel);
    strip_dev_dependencies_from_project(tmp.path())?;
    let tmp_manifest = tmp_manifest
        .canonicalize()
        .context("failed to canonicalize no-dev temp manifest")?;

    Ok((tmp, tmp_manifest))
}

fn copy_project_tree_for_resolve(source_dir: &Path, dest_dir: &Path) -> Result<()> {
    for entry in WalkDir::new(source_dir)
        .into_iter()
        .filter_entry(|entry| should_copy_resolve_entry(entry.path(), source_dir))
    {
        let entry = entry.context("failed to walk source tree for no-dev resolve")?;
        let path = entry.path();
        let rel = path
            .strip_prefix(source_dir)
            .with_context(|| format!("{} is not under {}", path.display(), source_dir.display()))?;
        if rel.as_os_str().is_empty() {
            continue;
        }

        let dest = dest_dir.join(rel);
        let file_type = entry.file_type();
        if file_type.is_dir() {
            fs::create_dir_all(&dest)
                .with_context(|| format!("failed to create {}", dest.display()))?;
        } else if file_type.is_file() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(path, &dest).with_context(|| {
                format!("failed to copy {} to {}", path.display(), dest.display())
            })?;
        } else if file_type.is_symlink() {
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to inspect symlink target {}", path.display()))?;
            if metadata.is_file() {
                fs::copy(path, &dest).with_context(|| {
                    format!("failed to copy {} to {}", path.display(), dest.display())
                })?;
            } else if metadata.is_dir() {
                fs::create_dir_all(&dest)
                    .with_context(|| format!("failed to create {}", dest.display()))?;
            }
        }
    }

    Ok(())
}

fn should_copy_resolve_entry(path: &Path, source_dir: &Path) -> bool {
    let Ok(rel) = path.strip_prefix(source_dir) else {
        return true;
    };
    let Some(first) = rel.components().next() else {
        return true;
    };
    let first = first.as_os_str();
    first != "target" && first != ".git"
}

fn strip_dev_dependencies_from_project(project_dir: &Path) -> Result<()> {
    for entry in WalkDir::new(project_dir)
        .into_iter()
        .filter_entry(|entry| should_copy_resolve_entry(entry.path(), project_dir))
    {
        let entry = entry.context("failed to walk project manifests for no-dev resolve")?;
        if !entry.file_type().is_file() || entry.file_name() != "Cargo.toml" {
            continue;
        }
        strip_dev_dependencies_from_manifest(entry.path())?;
    }
    Ok(())
}

fn strip_dev_dependencies_from_manifest(manifest: &Path) -> Result<()> {
    let content = fs::read_to_string(manifest)
        .with_context(|| format!("failed to read {}", manifest.display()))?;
    let mut doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", manifest.display()))?;

    if let Some(root) = doc.as_table_mut() {
        root.remove("dev-dependencies");
        root.remove("bench");
        root.remove("test");

        if let Some(targets) = root
            .get_mut("target")
            .and_then(|value| value.as_table_mut())
        {
            for (_, target) in targets.iter_mut() {
                if let Some(target_table) = target.as_table_mut() {
                    target_table.remove("dev-dependencies");
                }
            }
        }
    }

    let sanitized = toml::to_string_pretty(&doc)
        .with_context(|| format!("failed to serialize sanitized {}", manifest.display()))?;
    fs::write(manifest, sanitized)
        .with_context(|| format!("failed to write sanitized {}", manifest.display()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// BuildRequires output
// ---------------------------------------------------------------------------

fn buildrequires_from_lockfile(lockfile: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(lockfile)
        .with_context(|| format!("failed to read generated {}", lockfile.display()))?;
    let doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse generated {}", lockfile.display()))?;
    let packages = doc
        .get("package")
        .and_then(|value| value.as_array())
        .ok_or_else(|| anyhow::anyhow!("generated Cargo.lock has no package array"))?;

    let mut buildrequires = BTreeSet::new();
    for package in packages {
        let Some(package) = package.as_table() else {
            continue;
        };
        let Some(source) = package.get("source").and_then(|value| value.as_str()) else {
            continue;
        };
        if !source.starts_with("registry+") {
            continue;
        }

        let Some(name) = package.get("name").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(version) = package.get("version").and_then(|value| value.as_str()) else {
            continue;
        };
        let parsed_version = Version::parse(version)
            .with_context(|| format!("failed to parse lockfile version {}", version))?;
        let compat = calculate_compat_version(&parsed_version);
        let capability_name = name.replace('_', "-");
        let clean_version = clean_semver_without_build(&parsed_version);
        buildrequires.insert(format!(
            "BuildRequires: crate({}-{}) >= {}",
            capability_name, compat, clean_version
        ));
    }

    Ok(buildrequires.into_iter().collect())
}

// ---------------------------------------------------------------------------
// Cargo home / GlobalContext helpers
// ---------------------------------------------------------------------------

/// Create a temporary `CARGO_HOME` directory containing a `config.toml`
/// that replaces `crates-io` with the TakoPack local directory registry
/// and enables offline mode.
///
/// The returned `TempDir` must be kept alive for the duration of the
/// resolve operation.
fn make_cargo_home(registry_dir: &Path) -> Result<tempfile::TempDir> {
    let cargo_home = tempfile::tempdir().context("failed to create temp CARGO_HOME")?;

    let config_content = format!(
        r#"[source.crates-io]
replace-with = "takopack-local"

[source.takopack-local]
directory = "{}"

[net]
offline = true
"#,
        registry_dir.display()
    );

    fs::write(cargo_home.path().join("config.toml"), config_content)?;
    Ok(cargo_home)
}

/// Build a Cargo `GlobalContext` that uses the given directory as
/// `CARGO_HOME`.  This is the same pattern used elsewhere in TakoPack
/// (`GlobalContext::default()`) but with a custom home directory so the
/// source-replacement config we wrote is picked up.
fn make_global_context(cargo_home: &Path) -> Result<GlobalContext> {
    // Setting CARGO_HOME causes GlobalContext::default() to read
    // config from that directory.
    std::env::set_var("CARGO_HOME", cargo_home);
    let mut gctx = GlobalContext::default()?;

    // Configure offline mode via the API as well (belt-and-suspenders
    // alongside the config.toml `[net] offline = true`).
    gctx.configure(
        0,     // verbose
        false, // quiet
        None,  // color
        false, // frozen
        false, // locked
        true,  // offline
        &gctx.target_dir()?.map(|x| x.into_path_unlocked()),
        &[], // unstable flags
        &[], // cli config
    )?;

    Ok(gctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- detect_real_mode tests --

    #[test]
    fn test_real_mode_src_lib_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "").unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_real_mode_workspace() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(&manifest, "[workspace]\nmembers = [\"a\"]\n").unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(targets.has_workspace);
        assert!(detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_virtual_mode_lib_declared_but_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[lib]\nname = \"t\"\npath = \"src/lib.rs\"\n",
        )
        .unwrap();
        // Do NOT create src/lib.rs

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(!detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_virtual_mode_bin_declared_but_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"t\"\npath = \"src/main.rs\"\n",
        )
        .unwrap();
        // Do NOT create src/main.rs

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(!detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_real_mode_lib_declared_and_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[lib]\npath = \"src/lib.rs\"\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("src")).unwrap();
        fs::write(tmp.path().join("src/lib.rs"), "").unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_real_mode_bin_declared_and_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"myapp\"\npath = \"src/bin/myapp.rs\"\n",
        )
        .unwrap();
        fs::create_dir_all(tmp.path().join("src/bin")).unwrap();
        fs::write(tmp.path().join("src/bin/myapp.rs"), "fn main() {}").unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(detect_real_mode(&targets, tmp.path()));
    }

    #[test]
    fn test_virtual_mode_bare_toml() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nserde = \"1\"\n",
        )
        .unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(!detect_real_mode(&targets, tmp.path()));
    }

    // -- parse_manifest_targets tests --

    #[test]
    fn test_parse_targets_cargo_c_style() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            r#"[package]
name = "cargo-c"
version = "0.1.0"

[lib]
name = "cargo_c"
path = "src/lib.rs"

[[bin]]
name = "cargo-capi"
path = "src/bin/capi.rs"

[[bin]]
name = "cargo-cbuild"
path = "src/bin/cbuild.rs"
"#,
        )
        .unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(targets.has_lib_section);
        assert_eq!(targets.lib_path, Some(PathBuf::from("src/lib.rs")));
        assert_eq!(targets.bin_paths.len(), 2);
        assert_eq!(targets.bin_paths[0], PathBuf::from("src/bin/capi.rs"));
        assert_eq!(targets.bin_paths[1], PathBuf::from("src/bin/cbuild.rs"));
    }

    #[test]
    fn test_parse_targets_bin_without_path() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[[bin]]\nname = \"mybin\"\n",
        )
        .unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(targets.has_bin_sections);
        assert_eq!(targets.bin_paths, vec![PathBuf::from("src/bin/mybin.rs")]);
    }

    #[test]
    fn test_parse_targets_lib_without_path() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"t\"\nversion = \"0.1.0\"\n\n[lib]\nname = \"t\"\n",
        )
        .unwrap();

        let targets = parse_manifest_targets(&manifest).unwrap();
        assert!(targets.has_lib_section);
        assert_eq!(targets.lib_path, Some(PathBuf::from("src/lib.rs")));
    }

    // -- create_virtual_stubs tests --

    #[test]
    fn test_virtual_stubs_cargo_c_style() {
        let tmp = tempfile::tempdir().unwrap();
        let targets = ManifestTargets {
            has_workspace: false,
            lib_path: Some(PathBuf::from("src/lib.rs")),
            has_lib_section: true,
            bin_paths: vec![
                PathBuf::from("src/bin/capi.rs"),
                PathBuf::from("src/bin/cbuild.rs"),
            ],
            has_bin_sections: true,
        };

        create_virtual_stubs(tmp.path(), &targets).unwrap();

        assert!(tmp.path().join("src/lib.rs").exists());
        assert!(tmp.path().join("src/bin/capi.rs").exists());
        assert!(tmp.path().join("src/bin/cbuild.rs").exists());

        // Bin stubs should have fn main()
        let capi = fs::read_to_string(tmp.path().join("src/bin/capi.rs")).unwrap();
        assert!(capi.contains("fn main()"));
    }

    #[test]
    fn test_virtual_stubs_no_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let targets = ManifestTargets {
            has_workspace: false,
            lib_path: None,
            has_lib_section: false,
            bin_paths: vec![],
            has_bin_sections: false,
        };

        create_virtual_stubs(tmp.path(), &targets).unwrap();

        // Should create default src/lib.rs
        assert!(tmp.path().join("src/lib.rs").exists());
    }

    // -- no-dev sanitizer tests --

    #[test]
    fn test_strip_dev_dependencies_from_manifest() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            r#"[package]
name = "t"
version = "0.1.0"

[dependencies]
serde = "1"

[dev-dependencies]
criterion = "0.7"

[dev-dependencies.claim]
version = "0.5"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(unix)'.dev-dependencies]
tempfile = "3"

[target.'cfg(windows)'.dev-dependencies.claim]
version = "0.5"

[[bench]]
name = "bench"

[[test]]
name = "integration"
"#,
        )
        .unwrap();

        strip_dev_dependencies_from_manifest(&manifest).unwrap();

        let content = fs::read_to_string(&manifest).unwrap();
        let doc: toml::Value = toml::from_str(&content).unwrap();
        let root = doc.as_table().unwrap();

        assert!(root.get("dependencies").is_some());
        assert!(root.get("dev-dependencies").is_none());
        assert!(root.get("bench").is_none());
        assert!(root.get("test").is_none());

        let unix_target = root
            .get("target")
            .and_then(|target| target.get("cfg(unix)"))
            .and_then(|target| target.as_table())
            .unwrap();
        assert!(unix_target.get("dependencies").is_some());
        assert!(unix_target.get("dev-dependencies").is_none());

        let windows_target = root
            .get("target")
            .and_then(|target| target.get("cfg(windows)"))
            .and_then(|target| target.as_table())
            .unwrap();
        assert!(windows_target.get("dev-dependencies").is_none());
    }

    #[test]
    fn test_strip_dev_dependencies_from_project_workspace_members() {
        let tmp = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("member/src")).unwrap();
        fs::write(tmp.path().join("src_placeholder"), "").unwrap();
        fs::write(
            tmp.path().join("Cargo.toml"),
            r#"[workspace]
members = ["member"]

[package]
name = "root"
version = "0.1.0"

[dependencies]
serde = "1"

[build-dependencies]
cc = "1"

[dev-dependencies]
claim = "0.5"

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(unix)'.dev-dependencies]
tempfile = "3"
"#,
        )
        .unwrap();
        fs::write(
            tmp.path().join("member/Cargo.toml"),
            r#"[package]
name = "member"
version = "0.1.0"

[dependencies]
aho-corasick = "1"

[build-dependencies]
cc = "1"

[dev-dependencies]
claim = "0.5"

[dev-dependencies.pretty_assertions]
version = "1"

[target.'cfg(windows)'.dependencies]
windows-sys = "0.61"

[target.'cfg(windows)'.dev-dependencies]
tempfile = "3"

[target.'cfg(windows)'.dev-dependencies.claim]
version = "0.5"
"#,
        )
        .unwrap();

        strip_dev_dependencies_from_project(tmp.path()).unwrap();

        let root_content = fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        let root_doc: toml::Value = toml::from_str(&root_content).unwrap();
        let root = root_doc.as_table().unwrap();
        assert!(root.get("workspace").is_some());
        assert!(root.get("dependencies").is_some());
        assert!(root.get("build-dependencies").is_some());
        assert!(root.get("dev-dependencies").is_none());
        let unix_target = root
            .get("target")
            .and_then(|target| target.get("cfg(unix)"))
            .and_then(|target| target.as_table())
            .unwrap();
        assert!(unix_target.get("dependencies").is_some());
        assert!(unix_target.get("dev-dependencies").is_none());

        let member_content = fs::read_to_string(tmp.path().join("member/Cargo.toml")).unwrap();
        let member_doc: toml::Value = toml::from_str(&member_content).unwrap();
        let member = member_doc.as_table().unwrap();
        assert!(member.get("dependencies").is_some());
        assert!(member.get("build-dependencies").is_some());
        assert!(member.get("dev-dependencies").is_none());
        let windows_target = member
            .get("target")
            .and_then(|target| target.get("cfg(windows)"))
            .and_then(|target| target.as_table())
            .unwrap();
        assert!(windows_target.get("dependencies").is_some());
        assert!(windows_target.get("dev-dependencies").is_none());
    }

    // -- plan-missing parser tests --

    #[test]
    fn test_parse_missing_package_error() {
        let error = r#"cargo resolve failed

Caused by:
  no matching package named `crossterm` found
  location searched: directory source `/tmp/takopack-overlay-registry-a`
  required by package `yazi-cli v26.5.6 (/tmp/project)`
"#;

        let missing = parse_missing_package_error(error).unwrap();
        assert_eq!(missing.crate_name, "crossterm");
        let parent = missing.required_by.unwrap();
        assert_eq!(parent.name, "yazi-cli");
        assert_eq!(parent.version, "26.5.6");
        assert_eq!(parent.path, Some(PathBuf::from("/tmp/project")));
    }

    #[test]
    fn test_parse_missing_package_error_searched_package_name_format() {
        let error = r#"cargo resolve failed: no matching package found
searched package name: `twox-hash`
perhaps you meant:      gix-hash
location searched: directory source `/tmp/session/registry`
required by package `yazi-cli v26.5.6 (/tmp/project)`
"#;

        let missing = parse_missing_package_error(error).unwrap();
        assert_eq!(missing.crate_name, "twox-hash");
        assert_eq!(missing.required_by.unwrap().name, "yazi-cli");
    }

    #[test]
    fn test_infer_dependency_requirement_common_sections() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            r#"[package]
name = "parent"
version = "0.1.0"

[dependencies]
plain = "1"
alias = { package = "renamed-crate", version = "^2.3", optional = true }

[build-dependencies]
build-only = { version = "=0.4.1" }

[dev-dependencies]
dev-only = "5"

[target.'cfg(unix)'.dependencies]
unix-only = { version = "0.7" }
"#,
        )
        .unwrap();

        assert_eq!(
            infer_dependency_requirement(&manifest, "plain", false).unwrap(),
            Some("1".to_string())
        );
        assert_eq!(
            infer_dependency_requirement(&manifest, "renamed-crate", false).unwrap(),
            Some("^2.3".to_string())
        );
        assert_eq!(
            infer_dependency_requirement(&manifest, "build-only", false).unwrap(),
            Some("=0.4.1".to_string())
        );
        assert_eq!(
            infer_dependency_requirement(&manifest, "unix-only", false).unwrap(),
            Some("0.7".to_string())
        );
        assert_eq!(
            infer_dependency_requirement(&manifest, "dev-only", false).unwrap(),
            None
        );
        assert_eq!(
            infer_dependency_requirement(&manifest, "dev-only", true).unwrap(),
            Some("5".to_string())
        );
    }

    #[test]
    fn test_version_selection_failure_same_compat_is_conflict() {
        let tmp = tempfile::tempdir().unwrap();
        let provider = tmp.path().join("foo-1.5.0");
        fs::create_dir_all(&provider).unwrap();
        fs::write(
            provider.join("Cargo.toml"),
            r#"[package]
name = "foo"
version = "1.5.0"
"#,
        )
        .unwrap();

        let error = r#"cargo resolve failed

Caused by:
  failed to select a version for the requirement `foo = ">= 1.8"`
  candidate versions found which didn't match: 1.5.0
"#;

        let failure = parse_version_selection_failure(error).unwrap();
        assert_eq!(failure.crate_name, "foo");
        assert_eq!(failure.requirement, ">= 1.8");

        let same_compat =
            existing_same_compat_providers(tmp.path(), "foo", &Version::parse("1.8.0").unwrap());
        assert_eq!(same_compat.len(), 1);
        assert_eq!(same_compat[0].provider_name, "rust-foo-1");
        assert_eq!(same_compat[0].version, "1.5.0");
    }

    #[test]
    fn test_version_selection_failure_different_compat_is_missing_provider() {
        let tmp = tempfile::tempdir().unwrap();
        for version in ["0.5.2", "0.9.12+spec-1.1.0"] {
            let provider = tmp.path().join(format!("toml-{}", version));
            fs::create_dir_all(&provider).unwrap();
            fs::write(
                provider.join("Cargo.toml"),
                format!(
                    r#"[package]
name = "toml"
version = "{}"
"#,
                    version
                ),
            )
            .unwrap();
        }

        let same_compat =
            existing_same_compat_providers(tmp.path(), "toml", &Version::parse("1.1.2").unwrap());
        assert!(same_compat.is_empty());
    }

    #[test]
    fn test_plan_session_state_defaults_upgraded_crates() {
        let json = r#"{
  "schema_version": 1,
  "base_registry": "/tmp/registry",
  "added_crates": []
}"#;
        let state: PlanSessionState = serde_json::from_str(json).unwrap();
        assert!(state.upgraded_crates.is_empty());
    }

    #[test]
    fn test_format_required_by_strips_build_metadata() {
        let required_by = RequiredByPackage {
            name: "toml_datetime".to_string(),
            version: "0.7.3+spec-1.1.0".to_string(),
            path: None,
        };
        assert_eq!(format_required_by(&required_by), "toml_datetime 0.7.3");
    }

    // -- BuildRequires tests --

    #[test]
    fn test_buildrequires_from_lockfile_skips_non_registry_packages() {
        let tmp = tempfile::tempdir().unwrap();
        let lockfile = tmp.path().join("Cargo.lock");
        fs::write(
            &lockfile,
            r#"
version = 3

[[package]]
name = "root"
version = "0.1.0"

[[package]]
name = "local_dep"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.228"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokenizers"
version = "0.22.2"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tiny_http"
version = "0.12.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#,
        )
        .unwrap();

        let buildrequires = buildrequires_from_lockfile(&lockfile).unwrap();
        assert_eq!(
            buildrequires,
            vec![
                "BuildRequires: crate(serde-1) >= 1.0.228",
                "BuildRequires: crate(tiny-http-0.12) >= 0.12.0",
                "BuildRequires: crate(tokenizers-0.22) >= 0.22.2",
            ]
        );
    }

    // -- directory move helper tests --

    #[test]
    fn test_move_dir_or_copy_remove_falls_back_on_exdev() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src-provider");
        let dest = tmp.path().join("dest-provider");
        fs::create_dir_all(src.join("nested")).unwrap();
        fs::write(src.join("Cargo.toml"), "[package]\nname = \"x\"\n").unwrap();
        fs::write(src.join("nested/file.txt"), "payload\n").unwrap();

        move_dir_or_copy_remove_with(&src, &dest, |_, _| {
            Err(std::io::Error::from_raw_os_error(EXDEV_RAW_OS_ERROR))
        })
        .unwrap();

        assert!(
            !src.exists(),
            "source should be removed after copy fallback"
        );
        assert!(dest.is_dir(), "destination should exist after fallback");
        assert_eq!(
            fs::read_to_string(dest.join("Cargo.toml")).unwrap(),
            "[package]\nname = \"x\"\n"
        );
        assert_eq!(
            fs::read_to_string(dest.join("nested/file.txt")).unwrap(),
            "payload\n"
        );
    }

    // -- resolve_manifest tests --

    #[test]
    fn test_resolve_manifest_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        let (m, w) = resolve_manifest(tmp.path()).unwrap();
        assert_eq!(m, manifest);
        assert_eq!(w, tmp.path());
    }

    #[test]
    fn test_resolve_manifest_file() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = tmp.path().join("Cargo.toml");
        fs::write(
            &manifest,
            "[package]\nname = \"test\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        )
        .unwrap();

        let (m, w) = resolve_manifest(&manifest).unwrap();
        assert_eq!(m, manifest);
        assert_eq!(w, tmp.path());
    }

    #[test]
    fn test_resolve_manifest_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let result = resolve_manifest(tmp.path());
        assert!(result.is_err());
    }

    // -- Storage mode tests --

    /// Helper: create a minimal baseline registry with a single crate directory.
    fn create_test_baseline(base: &Path) {
        let crate_dir = base.join("foo-1.0.0");
        fs::create_dir_all(&crate_dir).unwrap();
        fs::write(
            crate_dir.join("Cargo.toml"),
            "[package]\nname = \"foo\"\nversion = \"1.0.0\"\nedition = \"2021\"\n",
        )
        .unwrap();
        fs::write(crate_dir.join("README.md"), "# foo\n").unwrap();
    }

    #[cfg(unix)]
    fn inode_of(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().ino()
    }

    #[cfg(unix)]
    struct FuseOverlayMountGuard(PathBuf);

    #[cfg(unix)]
    impl Drop for FuseOverlayMountGuard {
        fn drop(&mut self) {
            unmount_session_registry_best_effort(&self.0);
        }
    }

    #[cfg(unix)]
    fn fuse_overlay_mount_usable() -> bool {
        if !probe_fuse_overlayfs() {
            return false;
        }

        let Ok(tmp) = tempfile::tempdir() else {
            return false;
        };
        let lower = tmp.path().join("lower");
        let merged = tmp.path().join("merged");
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");
        if fs::create_dir_all(&lower).is_err()
            || fs::write(lower.join("probe.txt"), "probe\n").is_err()
            || fs::create_dir_all(&merged).is_err()
            || fs::create_dir_all(&upper).is_err()
            || fs::create_dir_all(&work).is_err()
        {
            return false;
        }

        match mount_fuse_overlay(&lower, &upper, &work, &merged) {
            Ok(()) => {
                let usable = merged.join("probe.txt").is_file();
                unmount_session_registry_best_effort(&merged);
                usable
            }
            Err(err) => {
                println!("SKIP: fuse-overlayfs mount is not usable: {:#}", err);
                false
            }
        }
    }

    /// Test 1: copy mode creates independent files (different inodes),
    /// and modifying the session file does not change the baseline.
    #[test]
    #[cfg(unix)]
    fn test_copy_mode_does_not_pollute_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let session = tmp.path().join("session");
        fs::create_dir_all(&session).unwrap();

        create_test_baseline(&base);

        let mut stats = OverlayCopyStats::default();
        copy_registry_tree(&base, &session, ResolvedStorageMethod::Copy, &mut stats).unwrap();

        let base_toml = base.join("foo-1.0.0/Cargo.toml");
        let session_toml = session.join("foo-1.0.0/Cargo.toml");

        // Files must exist in both locations.
        assert!(base_toml.is_file());
        assert!(session_toml.is_file());

        // Inodes must differ (not hardlinked).
        assert_ne!(
            inode_of(&base_toml),
            inode_of(&session_toml),
            "copy mode must create independent files, not hardlinks"
        );

        // Save original baseline content.
        let original_content = fs::read_to_string(&base_toml).unwrap();

        // Modify the session file.
        fs::write(&session_toml, "# modified in session\n").unwrap();

        // Baseline must be unchanged.
        let after_content = fs::read_to_string(&base_toml).unwrap();
        assert_eq!(
            original_content, after_content,
            "copy mode: modifying session file must not change baseline"
        );

        // Session file must have the new content.
        let session_content = fs::read_to_string(&session_toml).unwrap();
        assert_eq!(session_content, "# modified in session\n");

        // Stats verification.
        assert!(stats.copied_files > 0, "should have copied files");
        assert_eq!(stats.hardlinked_files, 0, "should not have hardlinked");
    }

    /// Test 2: auto mode does not use hardlink.
    /// Regardless of whether reflink or copy is chosen, files must have
    /// different inodes from the baseline.
    #[test]
    #[cfg(unix)]
    fn test_auto_mode_does_not_use_hardlink() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let session = tmp.path().join("session");
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");

        create_test_baseline(&base);

        let (resolved, stats, mounted) =
            initialize_registry_storage(&base, &session, &upper, &work, PlanSessionStorage::Auto)
                .unwrap();
        let _guard = mounted.then(|| FuseOverlayMountGuard(session.clone()));

        assert_ne!(
            resolved,
            ResolvedStorageMethod::Hardlink,
            "auto mode must never resolve to hardlink"
        );
        assert_eq!(stats.hardlinked_files, 0, "auto mode must not hardlink");

        let base_toml = base.join("foo-1.0.0/Cargo.toml");
        let session_toml = session.join("foo-1.0.0/Cargo.toml");

        if resolved == ResolvedStorageMethod::FuseOverlay {
            let original_content = fs::read_to_string(&base_toml).unwrap();
            fs::write(&session_toml, "# modified in auto fuse-overlay session\n").unwrap();
            assert_eq!(
                fs::read_to_string(&base_toml).unwrap(),
                original_content,
                "auto fuse-overlay must not modify the baseline"
            );

            let upper_toml = upper.join("foo-1.0.0/Cargo.toml");
            assert!(
                upper_toml.is_file(),
                "auto fuse-overlay should copy up writes"
            );
            assert_ne!(
                inode_of(&base_toml),
                inode_of(&upper_toml),
                "auto fuse-overlay: baseline and upper files must not share inodes"
            );
        } else {
            assert!(
                session_toml.is_file(),
                "session copy should contain baseline files"
            );

            assert_ne!(
                inode_of(&base_toml),
                inode_of(&session_toml),
                "auto mode: session and baseline files must not share inodes"
            );
        }
    }

    /// Test 3: hardlink mode preserves legacy behavior.
    /// Files should share the same inode.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_mode_preserves_compat() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let session = tmp.path().join("session");
        fs::create_dir_all(&session).unwrap();

        create_test_baseline(&base);

        let mut stats = OverlayCopyStats::default();
        copy_registry_tree(&base, &session, ResolvedStorageMethod::Hardlink, &mut stats).unwrap();

        let base_toml = base.join("foo-1.0.0/Cargo.toml");
        let session_toml = session.join("foo-1.0.0/Cargo.toml");

        // In hardlink mode, files should share the same inode.
        assert_eq!(
            inode_of(&base_toml),
            inode_of(&session_toml),
            "hardlink mode: files should share the same inode"
        );

        assert!(stats.hardlinked_files > 0, "should have hardlinked files");
    }

    // -- fuse-overlay storage mode tests --

    /// Test 4: auto mode prefers fuse-overlay when fuse-overlayfs is usable.
    #[test]
    #[cfg(unix)]
    fn test_auto_prefers_fuse_overlay_if_available() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let session = tmp.path().join("session");
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");

        create_test_baseline(&base);

        let (resolved, _stats, mounted) =
            initialize_registry_storage(&base, &session, &upper, &work, PlanSessionStorage::Auto)
                .unwrap();
        let _guard = mounted.then(|| FuseOverlayMountGuard(session.clone()));

        if fuse_overlay_mount_usable() {
            assert_eq!(
                resolved,
                ResolvedStorageMethod::FuseOverlay,
                "auto should prefer fuse-overlay when fuse-overlayfs can mount"
            );
        } else {
            println!(
                "SKIP: fuse-overlayfs is not usable; auto correctly fell back to {:?}",
                resolved
            );
            assert_ne!(resolved, ResolvedStorageMethod::Hardlink);
            assert_ne!(resolved, ResolvedStorageMethod::FuseOverlay);
        }
    }

    /// Test 5: fuse-overlay does not pollute baseline.
    #[test]
    #[cfg(unix)]
    fn test_fuse_overlay_no_baseline_pollution() {
        if !fuse_overlay_mount_usable() {
            println!(
                "SKIP: fuse-overlayfs is not usable; skipping fuse-overlay baseline pollution test"
            );
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let merged = tmp.path().join("merged");
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work");

        create_test_baseline(&base);
        fs::create_dir_all(&merged).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        mount_fuse_overlay(&base, &upper, &work, &merged).unwrap();
        let _guard = FuseOverlayMountGuard(merged.clone());

        let base_toml = base.join("foo-1.0.0/Cargo.toml");
        let merged_toml = merged.join("foo-1.0.0/Cargo.toml");

        // File should be visible through the overlay.
        assert!(
            merged_toml.is_file(),
            "merged overlay should show baseline files"
        );

        // Save original content.
        let original_content = fs::read_to_string(&base_toml).unwrap();

        // Modify through the overlay.
        fs::write(&merged_toml, "# modified in fuse-overlay session\n").unwrap();

        // Baseline must be unchanged.
        let after_content = fs::read_to_string(&base_toml).unwrap();
        assert_eq!(
            original_content, after_content,
            "fuse-overlay: modifying through overlay must not change baseline"
        );

        // Merged file should have new content.
        let merged_content = fs::read_to_string(&merged_toml).unwrap();
        assert_eq!(merged_content, "# modified in fuse-overlay session\n");

        // Upper dir should have the copy-up.
        let upper_toml = upper.join("foo-1.0.0/Cargo.toml");
        assert!(
            upper_toml.is_file(),
            "upper dir should contain copy-up file"
        );
    }

    /// Test 6: plan-reset unmounts fuse-overlay before removing session.
    #[test]
    #[cfg(unix)]
    fn test_plan_reset_unmounts_old_overlay() {
        if !fuse_overlay_mount_usable() {
            println!("SKIP: fuse-overlayfs is not usable; skipping plan-reset unmount test");
            return;
        }

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let session_root = tmp.path().join("session");
        let merged = session_root.join("registry");
        let upper = session_root.join("upper");
        let work = session_root.join("work");

        create_test_baseline(&base);
        fs::create_dir_all(&merged).unwrap();
        fs::create_dir_all(&upper).unwrap();
        fs::create_dir_all(&work).unwrap();

        mount_fuse_overlay(&base, &upper, &work, &merged).unwrap();
        assert!(
            is_mountpoint(&merged),
            "should be mounted after fuse-overlay mount"
        );

        // Simulate plan-reset: unmount then remove.
        unmount_session_registry_best_effort(&merged);
        assert!(
            !is_mountpoint(&merged),
            "should not be mounted after unmount"
        );

        // remove_dir_all should succeed now.
        fs::remove_dir_all(&session_root).unwrap();
        assert!(!session_root.exists(), "session root should be removed");
    }

    /// Test 7: explicit fuse-overlay failures do not fall back to copying.
    #[test]
    fn test_fuse_overlay_explicit_failure_no_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        let registry = tmp.path().join("registry");
        let upper = tmp.path().join("upper");
        let work = tmp.path().join("work-file");
        create_test_baseline(&base);
        fs::write(&work, "not a directory\n").unwrap();

        let result = initialize_registry_storage(
            &base,
            &registry,
            &upper,
            &work,
            PlanSessionStorage::FuseOverlay,
        );

        assert!(
            result.is_err(),
            "explicit fuse-overlay should fail when mount setup is invalid"
        );
        assert!(
            !registry.join("foo-1.0.0/Cargo.toml").exists(),
            "explicit fuse-overlay failure must not fall back to copy"
        );
    }
}
