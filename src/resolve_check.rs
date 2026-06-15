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

use std::collections::BTreeSet;
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

use crate::config::load_takopack_toml;
use crate::crates::resolve_crates_io_version_req;
use crate::errors::Result;
use crate::registry_sync::materialize_crate_from_crates_io;
use crate::util::{calculate_compat_version, rust_crate_output_names};

const MAX_PLAN_ITERATIONS: usize = 200;

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
    _tempdir: Option<tempfile::TempDir>,
    session_file: Option<PathBuf>,
    state: PlanSessionState,
    stats: OverlayCopyStats,
}

#[derive(Debug, Default)]
struct OverlayCopyStats {
    hardlinked_files: usize,
    copied_files: usize,
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
struct VersionConflict {
    crate_name: String,
    required: String,
    existing: Vec<ExistingProvider>,
}

#[derive(Debug, Clone)]
struct PlannedAdd {
    crate_name: String,
    version: Version,
}

#[derive(Debug, Clone)]
struct VersionSelectionFailure {
    crate_name: String,
    requirement: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct PlanSessionState {
    schema_version: u32,
    base_registry: String,
    added_crates: Vec<AddedCrateRecord>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
struct AddedCrateRecord {
    crate_name: String,
    version: String,
    rpm_name: String,
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
) -> Result<i32> {
    if !plan_missing && (plan_session.is_some() || plan_reset || !plan_add.is_empty()) {
        takopack_bail!("--plan-session, --plan-reset, and --plan-add require --plan-missing");
    }
    if plan_reset && plan_session.is_none() {
        takopack_bail!("--plan-reset requires --plan-session <NAME>");
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
    }
    println!();

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
) -> Result<i32> {
    println!("Planning missing providers using overlay registry...");
    println!();

    let mut overlay = create_overlay_registry(registry_dir, plan_session, plan_reset)?;
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

    let prepared = prepare_project_for_plan_missing(manifest, workdir, targets, is_real, no_dev)?;
    let mut planned_keys = BTreeSet::new();

    for _ in 0..MAX_PLAN_ITERATIONS {
        match cargo_resolve_prepared(&prepared.manifest, overlay.path(), print_buildrequires) {
            Ok(outcome) => {
                print_added_overlay_crates(&overlay.state.added_crates);
                println!();
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
                        &mut planned_keys,
                    ) {
                        Ok(()) => {
                            continue;
                        }
                        Err(plan_err) => {
                            print_added_overlay_crates(&overlay.state.added_crates);
                            println!();
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
                        &mut planned_keys,
                    ) {
                        Ok(None) => continue,
                        Ok(Some(conflict)) => {
                            print_added_overlay_crates(&overlay.state.added_crates);
                            println!();
                            println!("Result: failed");
                            println!();
                            print_version_conflicts(&[conflict]);
                            return Ok(1);
                        }
                        Err(plan_err) => {
                            print_added_overlay_crates(&overlay.state.added_crates);
                            println!();
                            println!("Result: failed");
                            eprintln!("{:#}", plan_err);
                            return Ok(1);
                        }
                    }
                }

                print_added_overlay_crates(&overlay.state.added_crates);
                println!();
                println!("Result: failed");
                println!();
                println!("Unknown failure:");
                eprintln!("{}", error_text);
                return Ok(1);
            }
        }
    }

    print_added_overlay_crates(&overlay.state.added_crates);
    println!();
    println!("Result: failed");
    eprintln!(
        "plan-missing exceeded max_plan_iterations = {}",
        MAX_PLAN_ITERATIONS
    );
    Ok(1)
}

impl OverlayRegistry {
    fn path(&self) -> &Path {
        &self.registry_dir
    }
}

impl PlanSessionState {
    fn new(base_registry: &Path) -> Self {
        Self {
            schema_version: 1,
            base_registry: base_registry.display().to_string(),
            added_crates: Vec::new(),
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
            strip_dev_dependencies_from_manifest(&tmp_manifest)?;
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
) -> Result<OverlayRegistry> {
    if let Some(name) = plan_session {
        return create_session_overlay_registry(registry_dir, name, plan_reset);
    }

    let tempdir = tempfile::Builder::new()
        .prefix("takopack-overlay-registry-")
        .tempdir()
        .context("failed to create temporary overlay registry")?;
    let registry_path = tempdir.path().to_path_buf();
    let mut stats = OverlayCopyStats::default();
    copy_registry_tree_with_hardlinks(registry_dir, &registry_path, &mut stats)?;
    Ok(OverlayRegistry {
        registry_dir: registry_path,
        _tempdir: Some(tempdir),
        session_file: None,
        state: PlanSessionState::new(registry_dir),
        stats,
    })
}

fn create_session_overlay_registry(
    registry_dir: &Path,
    session_name: &str,
    plan_reset: bool,
) -> Result<OverlayRegistry> {
    validate_plan_session_name(session_name)?;
    let session_root = plan_session_root()?.join(session_name);
    let registry_path = session_root.join("registry");
    let session_file = session_root.join("session.json");
    let mut stats = OverlayCopyStats::default();

    if plan_reset && session_root.exists() {
        fs::remove_dir_all(&session_root)
            .with_context(|| format!("failed to reset plan session {}", session_root.display()))?;
    }

    let state = if session_root.exists() {
        let state = load_plan_session_state(&session_file)?;
        if state.base_registry != registry_dir.display().to_string() {
            takopack_bail!(
                "plan session '{}' was created from {}, but current registry is {}; use --plan-reset to recreate it",
                session_name,
                state.base_registry,
                registry_dir.display()
            );
        }
        state
    } else {
        fs::create_dir_all(&registry_path)
            .with_context(|| format!("failed to create {}", registry_path.display()))?;
        copy_registry_tree_with_hardlinks(registry_dir, &registry_path, &mut stats)?;
        let state = PlanSessionState::new(registry_dir);
        save_plan_session_state(&session_file, &state)?;
        state
    };

    Ok(OverlayRegistry {
        registry_dir: registry_path,
        _tempdir: None,
        session_file: Some(session_file),
        state,
        stats,
    })
}

fn plan_session_root() -> Result<PathBuf> {
    let data_dir = dirs::data_dir().ok_or_else(|| {
        anyhow::anyhow!("cannot determine XDG_DATA_HOME / home directory for plan sessions")
    })?;
    Ok(data_dir.join("takopack").join("plan-sessions"))
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

fn add_crate_to_overlay(
    overlay: &mut OverlayRegistry,
    crate_name: &str,
    version: &Version,
) -> Result<()> {
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
    }

    Ok(())
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

fn copy_registry_tree_with_hardlinks(
    source_dir: &Path,
    dest_dir: &Path,
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
            hardlink_or_copy_file(path, &dest, stats)?;
        } else if file_type.is_symlink() {
            let metadata = fs::metadata(path)
                .with_context(|| format!("failed to inspect symlink target {}", path.display()))?;
            if metadata.is_file() {
                hardlink_or_copy_file(path, &dest, stats)?;
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

fn hardlink_or_copy_file(src: &Path, dest: &Path, stats: &mut OverlayCopyStats) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    match fs::hard_link(src, dest) {
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
    }
}

fn plan_and_materialize_missing_crate(
    missing: &MissingPackageError,
    root_manifest: &Path,
    overlay: &mut OverlayRegistry,
    no_dev: bool,
    planned_keys: &mut BTreeSet<String>,
) -> Result<()> {
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
    let planned_key = format!("{}-{}", missing.crate_name, selected_version);
    if !planned_keys.insert(planned_key.clone()) {
        takopack_bail!(
            "resolver still reports missing {} after adding {}; stopping to avoid a loop",
            missing.crate_name,
            planned_key
        );
    }

    add_crate_to_overlay(overlay, &missing.crate_name, &selected_version)?;
    Ok(())
}

fn print_added_overlay_crates(added_crates: &[AddedCrateRecord]) {
    println!("Added temporary/session crates:");
    if added_crates.is_empty() {
        println!("  (none)");
        return;
    }

    for added in added_crates {
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

fn print_version_conflicts(conflicts: &[VersionConflict]) {
    println!("Version conflicts:");
    for conflict in conflicts {
        println!("  {}", conflict.crate_name);
        println!("    required: {}", conflict.required);
        if conflict.existing.is_empty() {
            println!("    existing provider: (none found in overlay)");
        } else {
            for existing in &conflict.existing {
                println!(
                    "    existing provider: {} {}",
                    existing.provider_name, existing.version
                );
            }
        }
        println!("    action: review provider upgrade or add exact-version provider");
    }
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
    Some(VersionSelectionFailure {
        crate_name,
        requirement,
    })
}

fn plan_or_conflict_version_selection_failure(
    failure: &VersionSelectionFailure,
    overlay: &mut OverlayRegistry,
    planned_keys: &mut BTreeSet<String>,
) -> Result<Option<VersionConflict>> {
    let selected_version = resolve_crates_io_version_req(&failure.crate_name, &failure.requirement)
        .with_context(|| {
            format!(
                "failed to select crates.io version for {} {}",
                failure.crate_name, failure.requirement
            )
        })?;
    let same_compat =
        existing_same_compat_providers(overlay.path(), &failure.crate_name, &selected_version);

    if !same_compat.is_empty() {
        return Ok(Some(VersionConflict {
            crate_name: failure.crate_name.clone(),
            required: failure.requirement.clone(),
            existing: same_compat,
        }));
    }

    let planned_key = format!("{}-{}", failure.crate_name, selected_version);
    if !planned_keys.insert(planned_key.clone()) {
        takopack_bail!(
            "resolver still reports unsatisfied {} {} after adding {}; stopping to avoid a loop",
            failure.crate_name,
            failure.requirement,
            planned_key
        );
    }

    add_crate_to_overlay(overlay, &failure.crate_name, &selected_version)?;
    Ok(None)
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
    strip_dev_dependencies_from_manifest(&tmp_manifest)?;
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
        let clean_version = format!(
            "{}.{}.{}{}",
            parsed_version.major,
            parsed_version.minor,
            parsed_version.patch,
            if parsed_version.pre.is_empty() {
                String::new()
            } else {
                format!("-{}", parsed_version.pre)
            }
        );
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

[target.'cfg(unix)'.dependencies]
libc = "0.2"

[target.'cfg(unix)'.dev-dependencies]
tempfile = "3"

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
}
