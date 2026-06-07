use anyhow::{bail, Context, Result};
use clap::ValueEnum;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

use crate::config::{resolve_ruyispec_dir, ruyispec_package_root};
use crate::package::{PackageExecuteArgs, PackageExtractArgs, PackageInitArgs, PackageProcess};
use crate::repo_check::{
    build_buildreqs, build_repo_health_report, build_repo_index_with_options,
    build_repo_plan_with_options, BuildReqsKind, BuildReqsOptions, IndexedPackage, RepoIndex,
    RepoIndexOptions, RepoPlanOptions, RepoWarning,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum MigrateScope {
    Legacy,
    Dedupe,
    Exact,
    Prerelease,
    All,
}

#[derive(Debug, Clone)]
pub struct MigratePlanOptions {
    pub ruyispec: bool,
    pub index: Option<PathBuf>,
    pub scope: MigrateScope,
    pub batch_size: usize,
    pub output: PathBuf,
}

#[derive(Debug, Clone)]
pub struct MigrateApplyOptions {
    pub plan: PathBuf,
    pub package_root: PathBuf,
    pub staging: PathBuf,
    pub yes: bool,
    pub verify_apps: Vec<PathBuf>,
    pub skip_package_generation: bool,
    pub keep_old: bool,
    pub allow_prerelease: bool,
    pub apply_safe_subset: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub package_root: String,
    pub scope: MigrateScope,
    pub providers: Vec<MigrationProvider>,
    pub consumer_rewrites: Vec<ConsumerRewrite>,
    pub skipped: Vec<MigrationSkipped>,
    pub summary: MigrationPlanSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProvider {
    pub old_package: String,
    pub new_package: String,
    pub crate_name: String,
    pub crate_name_hyphen: String,
    pub version: String,
    pub old_capability_prefix: String,
    pub new_capability_prefix: String,
    pub old_dir: String,
    pub new_dir: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerRewrite {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationSkipped {
    pub package: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlanSummary {
    pub providers: usize,
    pub rewrites: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationApplyReport {
    pub plan: String,
    pub package_root: String,
    pub dry_run: bool,
    pub preflight: bool,
    pub providers_regenerated: usize,
    pub old_dirs_removed: usize,
    pub safe_providers: Vec<ProviderApplyStatus>,
    pub unsafe_providers: Vec<ProviderApplyStatus>,
    pub skipped_unsafe_providers: Vec<ProviderRef>,
    pub scoped_requires_rewritten: usize,
    pub unresolved_new_requires: Vec<UnresolvedNewRequire>,
    pub consumer_files_touched: usize,
    pub consumer_rewrite_occurrences: usize,
    pub old_prefix_remaining_count: usize,
    pub verify: Vec<MigrationVerifyReport>,
    pub git_diff_stat: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderApplyStatus {
    pub old_package: String,
    pub new_package: String,
    pub scoped_requires_rewritten: usize,
    pub unresolved_new_requires: Vec<UnresolvedNewRequire>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderRef {
    pub old_package: String,
    pub new_package: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationVerifyReport {
    pub cargo_toml: String,
    pub repo_plan_summary: crate::repo_check::RepoPlanSummary,
    pub repo_check_summary: crate::repo_check::RepoCheckSummary,
    pub buildreqs_summary: crate::repo_check::BuildReqsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnresolvedNewRequire {
    pub file: String,
    pub line: usize,
    pub capability: String,
    pub reason: String,
}

pub fn run_migrate_plan(options: MigratePlanOptions) -> Result<i32> {
    let (package_root, index) = load_plan_source(options.ruyispec, options.index.as_deref())?;
    let plan = build_migration_plan(&package_root, &index, options.scope, options.batch_size)?;

    if let Some(parent) = options.output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(
        &options.output,
        format!("{}\n", serde_json::to_string_pretty(&plan)?),
    )
    .with_context(|| format!("failed to write {}", options.output.display()))?;

    println!("Migration plan: {}", options.output.display());
    println!("package_root: {}", plan.package_root);
    println!("scope: {:?}", plan.scope);
    println!("providers: {}", plan.summary.providers);
    println!("rewrites: {}", plan.summary.rewrites);
    println!("skipped: {}", plan.summary.skipped);
    Ok(0)
}

pub fn run_migrate_apply(options: MigrateApplyOptions) -> Result<i32> {
    let (exit_code, report) = execute_migrate_apply(options)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(exit_code)
}

fn execute_migrate_apply(options: MigrateApplyOptions) -> Result<(i32, MigrationApplyReport)> {
    let content = fs::read_to_string(&options.plan)
        .with_context(|| format!("failed to read {}", options.plan.display()))?;
    let plan: MigrationPlan = serde_json::from_str(&content)
        .with_context(|| format!("failed to parse {}", options.plan.display()))?;

    let package_root = absolutize(&options.package_root)?;
    let mut notes = Vec::new();
    if !options.yes {
        notes.push("dry-run only; pass --yes to modify files".to_string());
        let report = MigrationApplyReport {
            plan: display_path(&options.plan),
            package_root: package_root.display().to_string(),
            dry_run: true,
            preflight: false,
            providers_regenerated: 0,
            old_dirs_removed: 0,
            safe_providers: Vec::new(),
            unsafe_providers: Vec::new(),
            skipped_unsafe_providers: Vec::new(),
            scoped_requires_rewritten: 0,
            unresolved_new_requires: Vec::new(),
            consumer_files_touched: 0,
            consumer_rewrite_occurrences: 0,
            old_prefix_remaining_count: 0,
            verify: Vec::new(),
            git_diff_stat: String::new(),
            notes,
        };
        return Ok((0, report));
    }

    ensure_apply_is_allowed(&plan, options.allow_prerelease)?;
    let original_index = build_repo_index_with_options(&package_root, RepoIndexOptions::default())?;
    let original_capabilities: BTreeSet<_> = original_index.capabilities.keys().cloned().collect();
    fs::create_dir_all(&options.staging)
        .with_context(|| format!("failed to create {}", options.staging.display()))?;

    let preflight = if options.apply_safe_subset {
        preflight_safe_subset(&plan, &options, &package_root, &original_capabilities)?
    } else {
        preflight_providers(
            &plan,
            &options,
            &package_root,
            &original_capabilities,
            &plan.providers,
        )?
    };

    let scoped_requires_rewritten = preflight.scoped_requires_rewritten();
    let unresolved_new_requires = preflight.unresolved_new_requires();
    let safe_providers = preflight.safe_statuses();
    let unsafe_providers = preflight.unsafe_statuses();
    let skipped_unsafe_providers = preflight.skipped_refs();

    if !unresolved_new_requires.is_empty() && !options.apply_safe_subset {
        notes.push(format!(
            "preflight found {} unresolved generated provider Requires; package_root was not modified",
            unresolved_new_requires.len()
        ));
        let report = MigrationApplyReport {
            plan: display_path(&options.plan),
            package_root: package_root.display().to_string(),
            dry_run: false,
            preflight: true,
            providers_regenerated: 0,
            old_dirs_removed: 0,
            safe_providers,
            unsafe_providers,
            skipped_unsafe_providers,
            scoped_requires_rewritten,
            unresolved_new_requires,
            consumer_files_touched: 0,
            consumer_rewrite_occurrences: 0,
            old_prefix_remaining_count: 0,
            verify: Vec::new(),
            git_diff_stat: String::new(),
            notes,
        };
        return Ok((1, report));
    }

    if options.apply_safe_subset && !skipped_unsafe_providers.is_empty() {
        notes.push(format!(
            "apply-safe-subset skipped {} unsafe providers",
            skipped_unsafe_providers.len()
        ));
    }
    if options.skip_package_generation {
        notes.push("provider generation skipped; copied/replaced local skeletons".to_string());
    }

    let mut providers_regenerated = 0usize;
    let mut old_dirs_removed = 0usize;
    for provider_result in &preflight.safe {
        let new_dir = package_root.join(&provider_result.provider.new_package);
        let old_dir = package_root.join(&provider_result.provider.old_package);
        copy_dir_replace(&provider_result.scoped_dir, &new_dir)?;
        providers_regenerated += 1;

        if !options.keep_old && old_dir.exists() {
            fs::remove_dir_all(&old_dir)
                .with_context(|| format!("failed to remove {}", old_dir.display()))?;
            old_dirs_removed += 1;
        }
    }

    let safe_rewrites =
        rewrites_for_providers(&plan.consumer_rewrites, &preflight.safe_provider_names());
    let rewrite_result = rewrite_consumers(&package_root, &safe_rewrites)?;
    let remaining = count_old_prefixes(&package_root, &safe_rewrites)?;
    let index = build_repo_index_with_options(&package_root, RepoIndexOptions::default())?;
    let verify = verify_apps(&options.verify_apps, &index)?;
    let git_diff_stat = git_diff_stat(&package_root).unwrap_or_default();

    if remaining > 0 {
        notes.push(format!(
            "{remaining} selected old capability prefix references remain"
        ));
    }

    let report = MigrationApplyReport {
        plan: display_path(&options.plan),
        package_root: package_root.display().to_string(),
        dry_run: false,
        preflight: true,
        providers_regenerated,
        old_dirs_removed,
        safe_providers,
        unsafe_providers,
        skipped_unsafe_providers,
        scoped_requires_rewritten,
        unresolved_new_requires,
        consumer_files_touched: rewrite_result.files_touched,
        consumer_rewrite_occurrences: rewrite_result.occurrences,
        old_prefix_remaining_count: remaining,
        verify,
        git_diff_stat,
        notes,
    };
    Ok((0, report))
}

pub fn build_migration_plan(
    package_root: &Path,
    index: &RepoIndex,
    scope: MigrateScope,
    batch_size: usize,
) -> Result<MigrationPlan> {
    let package_root = absolutize_existing_or_join(package_root)?;
    let packages_by_name: BTreeMap<_, _> = index
        .packages
        .iter()
        .map(|package| (package.rpm_name.as_str(), package))
        .collect();
    let mut providers = Vec::new();
    let mut skipped = Vec::new();
    let mut seen = BTreeSet::new();

    let include_legacy = matches!(scope, MigrateScope::Legacy | MigrateScope::All);
    let include_exact = matches!(scope, MigrateScope::Exact | MigrateScope::All);
    let include_prerelease = matches!(scope, MigrateScope::Prerelease);

    let mut warnings = index.warnings.clone();
    warnings.sort_by(|a, b| {
        (a.warning_type.as_str(), a.rpm_name.as_str(), a.cap.as_str()).cmp(&(
            b.warning_type.as_str(),
            b.rpm_name.as_str(),
            b.cap.as_str(),
        ))
    });

    for warning in &warnings {
        if providers.len() >= batch_size {
            break;
        }
        match warning.warning_type.as_str() {
            "legacy-compat-name" if include_legacy => {
                maybe_add_provider(
                    warning,
                    "legacy-compat-name",
                    &package_root,
                    &packages_by_name,
                    &mut seen,
                    &mut providers,
                    &mut skipped,
                );
            }
            "exact-version-package" if include_exact => {
                maybe_add_provider(
                    warning,
                    "exact-version-package",
                    &package_root,
                    &packages_by_name,
                    &mut seen,
                    &mut providers,
                    &mut skipped,
                );
            }
            "prerelease-version" if include_prerelease => {
                skipped.push(MigrationSkipped {
                    package: warning.rpm_name.clone(),
                    reason: "pre-release package is report-only by default".to_string(),
                    expected: warning.expected.clone(),
                    warning_type: Some(warning.warning_type.clone()),
                });
            }
            _ => {}
        }
    }

    if matches!(scope, MigrateScope::Dedupe | MigrateScope::All) {
        let report = build_repo_health_report(Path::new("<in-memory-index>"), index);
        for action in report.dedupe {
            skipped.push(MigrationSkipped {
                package: action.slot,
                reason: if action.manual_review {
                    format!("dedupe needs manual review; keep {}", action.keep)
                } else {
                    format!(
                        "dedupe report-only in this experimental version; keep {}",
                        action.keep
                    )
                },
                expected: Some(action.keep),
                warning_type: Some("dedupe".to_string()),
            });
        }
    }

    let mut consumer_rewrites: Vec<_> = providers
        .iter()
        .map(|provider| ConsumerRewrite {
            from: provider.old_capability_prefix.clone(),
            to: provider.new_capability_prefix.clone(),
        })
        .collect();
    consumer_rewrites.sort_by(|a, b| a.from.cmp(&b.from));
    consumer_rewrites.dedup_by(|a, b| a.from == b.from);

    Ok(MigrationPlan {
        package_root: package_root.display().to_string(),
        scope,
        summary: MigrationPlanSummary {
            providers: providers.len(),
            rewrites: consumer_rewrites.len(),
            skipped: skipped.len(),
        },
        providers,
        consumer_rewrites,
        skipped,
    })
}

fn load_plan_source(ruyispec: bool, index_path: Option<&Path>) -> Result<(PathBuf, RepoIndex)> {
    let package_root = if ruyispec {
        let ruyispec_dir = resolve_ruyispec_dir(None, true)?;
        Some(ruyispec_package_root(&ruyispec_dir))
    } else {
        None
    };

    let index = match index_path {
        Some(path) => {
            let content = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            serde_json::from_str(&content)
                .with_context(|| format!("failed to parse {}", path.display()))?
        }
        None => {
            let Some(package_root) = package_root.as_deref() else {
                bail!("pass --index or --ruyispec for migrate-plan");
            };
            build_repo_index_with_options(package_root, RepoIndexOptions::default())?
        }
    };

    let package_root = match package_root {
        Some(root) => root,
        None => infer_package_root_from_index(&index)?,
    };
    Ok((package_root, index))
}

fn maybe_add_provider(
    warning: &RepoWarning,
    reason: &str,
    package_root: &Path,
    packages_by_name: &BTreeMap<&str, &IndexedPackage>,
    seen: &mut BTreeSet<String>,
    providers: &mut Vec<MigrationProvider>,
    skipped: &mut Vec<MigrationSkipped>,
) {
    if !seen.insert(warning.rpm_name.clone()) {
        return;
    }
    let Some(package) = packages_by_name.get(warning.rpm_name.as_str()) else {
        skipped.push(MigrationSkipped {
            package: warning.rpm_name.clone(),
            reason: "warning package is not indexed".to_string(),
            expected: warning.expected.clone(),
            warning_type: Some(warning.warning_type.clone()),
        });
        return;
    };
    let Some(new_package) = warning.expected.clone() else {
        skipped.push(MigrationSkipped {
            package: warning.rpm_name.clone(),
            reason: "warning has no expected package name".to_string(),
            expected: None,
            warning_type: Some(warning.warning_type.clone()),
        });
        return;
    };
    if warning.rpm_name == new_package {
        skipped.push(MigrationSkipped {
            package: warning.rpm_name.clone(),
            reason: "old package already matches expected name".to_string(),
            expected: Some(new_package),
            warning_type: Some(warning.warning_type.clone()),
        });
        return;
    }

    let old_capability = if warning.cap.is_empty() {
        main_capability(package).unwrap_or_default()
    } else {
        warning.cap.clone()
    };
    let Some(old_capability_prefix) = capability_prefix(&old_capability) else {
        skipped.push(MigrationSkipped {
            package: warning.rpm_name.clone(),
            reason: "could not derive old crate capability prefix".to_string(),
            expected: Some(new_package),
            warning_type: Some(warning.warning_type.clone()),
        });
        return;
    };
    let Some(new_capability_prefix) = rust_package_capability_prefix(&new_package) else {
        skipped.push(MigrationSkipped {
            package: warning.rpm_name.clone(),
            reason: "could not derive new crate capability prefix".to_string(),
            expected: Some(new_package),
            warning_type: Some(warning.warning_type.clone()),
        });
        return;
    };

    providers.push(MigrationProvider {
        old_package: warning.rpm_name.clone(),
        new_package: new_package.clone(),
        crate_name: package.crate_name.clone(),
        crate_name_hyphen: package.crate_name.replace('_', "-"),
        version: package.version.clone(),
        old_capability_prefix,
        new_capability_prefix,
        old_dir: package_root.join(&warning.rpm_name).display().to_string(),
        new_dir: package_root.join(&new_package).display().to_string(),
        reason: reason.to_string(),
    });
}

fn ensure_apply_is_allowed(plan: &MigrationPlan, allow_prerelease: bool) -> Result<()> {
    if allow_prerelease {
        return Ok(());
    }
    if let Some(provider) = plan
        .providers
        .iter()
        .find(|provider| provider.reason == "prerelease-version")
    {
        bail!(
            "plan contains pre-release provider {}; pass --allow-prerelease to apply",
            provider.old_package
        );
    }
    Ok(())
}

fn generate_provider(provider: &MigrationProvider, staging: &Path) -> Result<PathBuf> {
    let target = staging.join(&provider.new_package);
    if target.exists() {
        fs::remove_dir_all(&target)
            .with_context(|| format!("failed to remove {}", target.display()))?;
    }

    let init = PackageInitArgs {
        crate_name: provider.crate_name.clone(),
        version: Some(provider.version.clone()),
        config: None,
    };
    let mut extract = PackageExtractArgs {
        directory: Some(target.clone()),
    };
    let finish = PackageExecuteArgs {
        changelog_ready: true,
        copyright_guess_harder: false,
        no_overlay_write_back: true,
        lockfile_deps: None,
    };

    let mut process = PackageProcess::init(init)?;
    let output_names = crate::util::rust_crate_output_names(
        process.crate_info().crate_name(),
        process.crate_info().version(),
    );
    let final_output =
        crate::util::package_final_output_dir(extract.directory.as_deref(), &output_names)?;
    extract.directory = Some(final_output.clone());

    process.extract(extract)?;
    process.apply_overrides()?;
    process.prepare_orig_tarball()?;
    process.prepare_takopack_folder(finish)?;

    let output_path = process
        .output_dir
        .as_ref()
        .context("missing package output dir")?;
    let source_spec = output_path.join("takopack").join(&output_names.spec_file);
    if !source_spec.exists() {
        bail!("generated spec not found at {}", source_spec.display());
    }
    fs::create_dir_all(&final_output)
        .with_context(|| format!("failed to create {}", final_output.display()))?;
    fs::copy(&source_spec, final_output.join(&output_names.spec_file))
        .with_context(|| format!("failed to copy generated spec for {}", provider.new_package))?;
    crate::util::copy_original_cargo_toml_to_dir(output_path, &final_output)?;

    if output_path == &final_output {
        let takopack_dir = output_path.join("takopack");
        if takopack_dir.exists() {
            fs::remove_dir_all(takopack_dir)?;
        }
        let final_spec = final_output.join(&output_names.spec_file);
        let final_cargo = final_output.join("Cargo.toml");
        for entry in fs::read_dir(output_path)? {
            let path = entry?.path();
            if path != final_spec && path != final_cargo {
                if path.is_dir() {
                    fs::remove_dir_all(path)?;
                } else {
                    fs::remove_file(path)?;
                }
            }
        }
    } else if output_path.exists() {
        fs::remove_dir_all(output_path)?;
    }

    Ok(final_output)
}

fn copy_provider_skeleton(
    provider: &MigrationProvider,
    old_dir: &Path,
    new_dir: &Path,
) -> Result<()> {
    if !old_dir.is_dir() {
        bail!(
            "old provider directory does not exist: {}",
            old_dir.display()
        );
    }
    copy_dir_replace(old_dir, new_dir)?;
    rewrite_tree_literals(new_dir, &provider.old_package, &provider.new_package)?;
    if let (Some(old_pkgname), Some(new_pkgname)) = (
        provider.old_package.strip_prefix("rust-"),
        provider.new_package.strip_prefix("rust-"),
    ) {
        rewrite_tree_literals(new_dir, old_pkgname, new_pkgname)?;
    }
    rewrite_tree_literals(
        new_dir,
        &provider.old_capability_prefix,
        &provider.new_capability_prefix,
    )?;
    Ok(())
}

fn rewrite_consumers(package_root: &Path, rewrites: &[ConsumerRewrite]) -> Result<RewriteResult> {
    let mut files_touched = 0usize;
    let mut occurrences = 0usize;
    for entry in WalkDir::new(package_root) {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension().map_or(true, |ext| ext != "spec")
        {
            continue;
        }
        let path = entry.path();
        let original = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut updated = original.clone();
        let mut file_occurrences = 0usize;
        for rewrite in rewrites {
            let pattern = Regex::new(&format!(r"{}([/)])", regex::escape(&rewrite.from)))?;
            let count = pattern.find_iter(&updated).count();
            if count > 0 {
                file_occurrences += count;
                let replacement = format!("{}$1", rewrite.to);
                updated = pattern
                    .replace_all(&updated, replacement.as_str())
                    .into_owned();
            }
        }
        if updated != original {
            fs::write(path, updated)
                .with_context(|| format!("failed to write {}", path.display()))?;
            files_touched += 1;
            occurrences += file_occurrences;
        }
    }
    Ok(RewriteResult {
        files_touched,
        occurrences,
    })
}

#[derive(Debug, Clone)]
struct RewriteResult {
    files_touched: usize,
    occurrences: usize,
}

#[derive(Debug, Clone)]
struct ScopedRequiresResult {
    rewritten: usize,
    unresolved: Vec<UnresolvedNewRequire>,
}

#[derive(Debug, Clone)]
struct PreflightProviderResult {
    provider: MigrationProvider,
    scoped_dir: PathBuf,
    scoped_requires_rewritten: usize,
    unresolved_new_requires: Vec<UnresolvedNewRequire>,
}

#[derive(Debug, Clone)]
struct PreflightResult {
    safe: Vec<PreflightProviderResult>,
    unsafe_providers: Vec<PreflightProviderResult>,
}

impl PreflightResult {
    fn scoped_requires_rewritten(&self) -> usize {
        self.safe
            .iter()
            .chain(self.unsafe_providers.iter())
            .map(|provider| provider.scoped_requires_rewritten)
            .sum()
    }

    fn unresolved_new_requires(&self) -> Vec<UnresolvedNewRequire> {
        self.unsafe_providers
            .iter()
            .flat_map(|provider| provider.unresolved_new_requires.clone())
            .collect()
    }

    fn safe_statuses(&self) -> Vec<ProviderApplyStatus> {
        self.safe.iter().map(provider_apply_status).collect()
    }

    fn unsafe_statuses(&self) -> Vec<ProviderApplyStatus> {
        self.unsafe_providers
            .iter()
            .map(provider_apply_status)
            .collect()
    }

    fn skipped_refs(&self) -> Vec<ProviderRef> {
        self.unsafe_providers
            .iter()
            .map(|provider| provider_ref(&provider.provider))
            .collect()
    }

    fn safe_provider_names(&self) -> BTreeSet<String> {
        self.safe
            .iter()
            .map(|provider| provider.provider.old_package.clone())
            .collect()
    }
}

fn provider_apply_status(provider: &PreflightProviderResult) -> ProviderApplyStatus {
    ProviderApplyStatus {
        old_package: provider.provider.old_package.clone(),
        new_package: provider.provider.new_package.clone(),
        scoped_requires_rewritten: provider.scoped_requires_rewritten,
        unresolved_new_requires: provider.unresolved_new_requires.clone(),
    }
}

fn provider_ref(provider: &MigrationProvider) -> ProviderRef {
    ProviderRef {
        old_package: provider.old_package.clone(),
        new_package: provider.new_package.clone(),
    }
}

fn preflight_safe_subset(
    plan: &MigrationPlan,
    options: &MigrateApplyOptions,
    package_root: &Path,
    original_capabilities: &BTreeSet<String>,
) -> Result<PreflightResult> {
    let mut candidates = plan.providers.clone();
    let mut last_result = PreflightResult {
        safe: Vec::new(),
        unsafe_providers: Vec::new(),
    };

    loop {
        let result = preflight_providers(
            plan,
            options,
            package_root,
            original_capabilities,
            &candidates,
        )?;
        let unsafe_names: BTreeSet<_> = result
            .unsafe_providers
            .iter()
            .map(|provider| provider.provider.old_package.clone())
            .collect();
        if unsafe_names.is_empty() {
            let mut final_result = result;
            final_result
                .unsafe_providers
                .extend(last_result.unsafe_providers);
            return Ok(final_result);
        }

        let next_candidates: Vec<_> = candidates
            .into_iter()
            .filter(|provider| !unsafe_names.contains(&provider.old_package))
            .collect();
        last_result.unsafe_providers.extend(result.unsafe_providers);

        if next_candidates.is_empty() {
            return Ok(PreflightResult {
                safe: Vec::new(),
                unsafe_providers: last_result.unsafe_providers,
            });
        }
        candidates = next_candidates;
    }
}

fn preflight_providers(
    _plan: &MigrationPlan,
    options: &MigrateApplyOptions,
    package_root: &Path,
    original_capabilities: &BTreeSet<String>,
    providers: &[MigrationProvider],
) -> Result<PreflightResult> {
    let raw_root = options.staging.join("__preflight_raw");
    let scoped_root = options.staging.join("__preflight_scoped");
    if raw_root.exists() {
        fs::remove_dir_all(&raw_root)
            .with_context(|| format!("failed to remove {}", raw_root.display()))?;
    }
    if scoped_root.exists() {
        fs::remove_dir_all(&scoped_root)
            .with_context(|| format!("failed to remove {}", scoped_root.display()))?;
    }
    fs::create_dir_all(&raw_root)
        .with_context(|| format!("failed to create {}", raw_root.display()))?;
    fs::create_dir_all(&scoped_root)
        .with_context(|| format!("failed to create {}", scoped_root.display()))?;

    let selected_new_prefixes: BTreeSet<_> = providers
        .iter()
        .map(|provider| provider.new_capability_prefix.clone())
        .collect();
    let mut safe = Vec::new();
    let mut unsafe_providers = Vec::new();

    for provider in providers {
        let old_dir = package_root.join(&provider.old_package);
        let raw_dir = if options.skip_package_generation {
            let raw_dir = raw_root.join(&provider.new_package);
            copy_provider_skeleton(provider, &old_dir, &raw_dir)?;
            raw_dir
        } else {
            generate_provider(provider, &raw_root)?
        };
        let scoped_dir = scoped_root.join(&provider.new_package);
        copy_dir_replace(&raw_dir, &scoped_dir)?;
        let scoped_result =
            scope_provider_requires(&scoped_dir, original_capabilities, &selected_new_prefixes)?;
        let result = PreflightProviderResult {
            provider: provider.clone(),
            scoped_dir,
            scoped_requires_rewritten: scoped_result.rewritten,
            unresolved_new_requires: scoped_result.unresolved,
        };
        if result.unresolved_new_requires.is_empty() {
            safe.push(result);
        } else {
            unsafe_providers.push(result);
        }
    }

    Ok(PreflightResult {
        safe,
        unsafe_providers,
    })
}

fn rewrites_for_providers(
    rewrites: &[ConsumerRewrite],
    safe_old_packages: &BTreeSet<String>,
) -> Vec<ConsumerRewrite> {
    rewrites
        .iter()
        .filter(|rewrite| {
            safe_old_packages.iter().any(|old_package| {
                rust_package_capability_prefix(old_package)
                    .as_deref()
                    .is_some_and(|prefix| prefix == rewrite.from)
            })
        })
        .cloned()
        .collect()
}

fn scope_provider_requires(
    provider_dir: &Path,
    repo_capabilities: &BTreeSet<String>,
    selected_new_prefixes: &BTreeSet<String>,
) -> Result<ScopedRequiresResult> {
    let crate_capability = Regex::new(r"crate\([^)]+\)")?;
    let mut rewritten = 0usize;
    let mut unresolved = Vec::new();

    for entry in WalkDir::new(provider_dir) {
        let entry = entry?;
        if !entry.file_type().is_file()
            || entry.path().extension().map_or(true, |ext| ext != "spec")
        {
            continue;
        }

        let path = entry.path();
        let original = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let mut changed = false;
        let mut updated_lines = Vec::new();

        for (line_index, line) in original.lines().enumerate() {
            if !line.trim_start().starts_with("Requires:") {
                updated_lines.push(line.to_string());
                continue;
            }

            let mut line_unresolved = Vec::new();
            let updated = crate_capability
                .replace_all(line, |captures: &regex::Captures<'_>| {
                    let capability = captures.get(0).expect("full match").as_str();
                    if should_keep_generated_require(
                        capability,
                        repo_capabilities,
                        selected_new_prefixes,
                    ) {
                        return capability.to_string();
                    }

                    if let Some(fallback) = dotted_major_fallback_capability(capability) {
                        if repo_capabilities.contains(&fallback) {
                            rewritten += 1;
                            changed = true;
                            return fallback;
                        }
                    }

                    line_unresolved.push(UnresolvedNewRequire {
                        file: path.display().to_string(),
                        line: line_index + 1,
                        capability: capability.to_string(),
                        reason: "capability is outside this migration batch and no existing dotted fallback was found".to_string(),
                    });
                    capability.to_string()
                })
                .into_owned();

            unresolved.extend(line_unresolved);
            updated_lines.push(updated);
        }

        if changed {
            let mut updated = updated_lines.join("\n");
            if original.ends_with('\n') {
                updated.push('\n');
            }
            fs::write(path, updated)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
    }

    Ok(ScopedRequiresResult {
        rewritten,
        unresolved,
    })
}

fn should_keep_generated_require(
    capability: &str,
    repo_capabilities: &BTreeSet<String>,
    selected_new_prefixes: &BTreeSet<String>,
) -> bool {
    if !is_literal_crate_capability(capability) {
        return true;
    }
    if selected_new_prefixes
        .iter()
        .any(|prefix| capability_matches_prefix(capability, prefix))
    {
        return true;
    }
    repo_capabilities.contains(capability)
}

fn is_literal_crate_capability(capability: &str) -> bool {
    capability
        .strip_prefix("crate(")
        .and_then(|value| value.strip_suffix(')'))
        .is_some_and(|inner| !inner.contains('%') && !inner.contains('{') && !inner.contains('}'))
}

fn capability_matches_prefix(capability: &str, prefix: &str) -> bool {
    capability
        .strip_prefix(prefix)
        .is_some_and(|suffix| suffix == ")" || suffix.starts_with('/'))
}

fn dotted_major_fallback_capability(capability: &str) -> Option<String> {
    let inner = capability.strip_prefix("crate(")?.strip_suffix(')')?;
    let (package, feature) = inner.split_once('/').unwrap_or((inner, ""));
    let (name, branch) = package.rsplit_once('-')?;
    if branch.contains('.') {
        return None;
    }
    let major = branch.parse::<u64>().ok()?;
    if major == 0 {
        return None;
    }

    let fallback_package = format!("{name}-{major}.0");
    if feature.is_empty() {
        Some(format!("crate({fallback_package})"))
    } else {
        Some(format!("crate({fallback_package}/{feature})"))
    }
}

fn count_old_prefixes(package_root: &Path, rewrites: &[ConsumerRewrite]) -> Result<usize> {
    let mut count = 0usize;
    let patterns: Vec<_> = rewrites
        .iter()
        .map(|rewrite| Regex::new(&format!(r"{}([/)])", regex::escape(&rewrite.from))))
        .collect::<std::result::Result<_, _>>()?;
    for entry in WalkDir::new(package_root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let content = fs::read_to_string(entry.path()).unwrap_or_default();
        for pattern in &patterns {
            count += pattern.find_iter(&content).count();
        }
    }
    Ok(count)
}

fn verify_apps(cargo_tomls: &[PathBuf], index: &RepoIndex) -> Result<Vec<MigrationVerifyReport>> {
    let mut reports = Vec::new();
    for cargo_toml in cargo_tomls {
        let plan = build_repo_plan_with_options(
            cargo_toml,
            index,
            &RepoPlanOptions {
                check_transitive: true,
                json: true,
                include_global_warnings: false,
            },
        )?;
        let buildreqs = build_buildreqs(
            cargo_toml,
            Some(index),
            &BuildReqsOptions {
                kind: BuildReqsKind::App,
                include_build: true,
                include_dev: false,
                json: true,
                check: false,
            },
        )?;
        reports.push(MigrationVerifyReport {
            cargo_toml: cargo_toml.display().to_string(),
            repo_plan_summary: plan.summary,
            repo_check_summary: plan.repo_check_summary,
            buildreqs_summary: buildreqs.summary,
        });
    }
    Ok(reports)
}

fn rewrite_tree_literals(root: &Path, from: &str, to: &str) -> Result<()> {
    for entry in WalkDir::new(root) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        let original = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let updated = original.replace(from, to);
        if updated != original {
            fs::write(path, updated)
                .with_context(|| format!("failed to write {}", path.display()))?;
        }
    }
    Ok(())
}

fn copy_dir_replace(src: &Path, dst: &Path) -> Result<()> {
    if dst.exists() {
        fs::remove_dir_all(dst).with_context(|| format!("failed to remove {}", dst.display()))?;
    }
    fs::create_dir_all(dst).with_context(|| format!("failed to create {}", dst.display()))?;
    for entry in WalkDir::new(src) {
        let entry = entry?;
        let path = entry.path();
        if path == src {
            continue;
        }
        let rel = path.strip_prefix(src)?;
        let target = dst.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
        } else if entry.file_type().is_file() {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("failed to create {}", parent.display()))?;
            }
            fs::copy(path, &target).with_context(|| {
                format!("failed to copy {} to {}", path.display(), target.display())
            })?;
        }
    }
    Ok(())
}

fn main_capability(package: &IndexedPackage) -> Option<String> {
    package
        .provides
        .iter()
        .find(|provide| provide.subpackage == "main" && !provide.cap.contains('/'))
        .map(|provide| provide.cap.clone())
        .or_else(|| {
            package
                .provides
                .iter()
                .find(|provide| !provide.cap.contains('/'))
                .map(|provide| provide.cap.clone())
        })
}

fn capability_prefix(capability: &str) -> Option<String> {
    capability
        .strip_prefix("crate(")
        .and_then(|value| value.strip_suffix(')'))
        .map(|value| format!("crate({value}"))
}

fn rust_package_capability_prefix(package_name: &str) -> Option<String> {
    package_name
        .strip_prefix("rust-")
        .filter(|value| !value.is_empty())
        .map(|value| format!("crate({value}"))
}

fn infer_package_root_from_index(index: &RepoIndex) -> Result<PathBuf> {
    let mut dirs = index
        .packages
        .iter()
        .filter_map(|package| {
            let path = PathBuf::from(&package.spec_path);
            let path = if path.is_absolute() {
                path
            } else {
                std::env::current_dir().ok()?.join(path)
            };
            path.parent().map(Path::to_path_buf)
        })
        .collect::<Vec<_>>();
    dirs.sort();
    dirs.dedup();
    let Some(mut common) = dirs.first().cloned() else {
        bail!("cannot infer package root from an empty repo index");
    };
    for dir in dirs.iter().skip(1) {
        while !dir.starts_with(&common) {
            if !common.pop() {
                bail!("cannot infer package root from repo index spec paths");
            }
        }
    }
    Ok(common)
}

fn absolutize(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

fn absolutize_existing_or_join(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).or_else(|_| absolutize(path))
}

fn git_diff_stat(package_root: &Path) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(package_root)
        .arg("diff")
        .arg("--stat")
        .output()
        .with_context(|| "failed to run git diff --stat")?;
    if !output.status.success() {
        return Ok(String::new());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn display_path(path: &Path) -> String {
    match std::env::current_dir()
        .ok()
        .and_then(|cwd| path.strip_prefix(cwd).ok().map(Path::to_path_buf))
    {
        Some(relative) => relative.display().to_string(),
        None => path.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo_check::{CapabilityProvider, IndexedPackage, ProvideRecord, RepoIndexSummary};

    fn package(name: &str, crate_name: &str, pkgname: &str, version: &str) -> IndexedPackage {
        IndexedPackage {
            rpm_name: name.to_string(),
            version: version.to_string(),
            crate_name: crate_name.to_string(),
            pkgname: pkgname.to_string(),
            spec_path: format!("/repo/SPECS/{name}/{name}.spec"),
            provides: vec![ProvideRecord {
                cap: format!("crate({pkgname})"),
                version: version.to_string(),
                subpackage: "main".to_string(),
            }],
            requires: Vec::new(),
        }
    }

    fn package_with_provides(
        name: &str,
        crate_name: &str,
        version: &str,
        provides: &[&str],
    ) -> IndexedPackage {
        IndexedPackage {
            rpm_name: name.to_string(),
            version: version.to_string(),
            crate_name: crate_name.to_string(),
            pkgname: provides
                .first()
                .and_then(|cap| cap.strip_prefix("crate("))
                .and_then(|cap| cap.strip_suffix(')'))
                .unwrap_or_default()
                .to_string(),
            spec_path: format!("/repo/SPECS/{name}/{name}.spec"),
            provides: provides
                .iter()
                .map(|cap| ProvideRecord {
                    cap: cap.to_string(),
                    version: version.to_string(),
                    subpackage: "main".to_string(),
                })
                .collect(),
            requires: Vec::new(),
        }
    }

    fn legacy_warning(name: &str, cap: &str, expected: &str) -> RepoWarning {
        RepoWarning {
            warning_type: "legacy-compat-name".to_string(),
            rpm_name: name.to_string(),
            subpackage: "main".to_string(),
            cap: cap.to_string(),
            message: String::new(),
            normalized_version: None,
            requirement: None,
            line: None,
            expected: Some(expected.to_string()),
        }
    }

    #[test]
    fn legacy_plan_builds_provider_and_rewrite() {
        let index = RepoIndex {
            packages: vec![package("rust-foo-1.0", "foo", "foo-1.0", "1.2.3")],
            capabilities: BTreeMap::from([(
                "crate(foo-1.0)".to_string(),
                vec![CapabilityProvider {
                    rpm_name: "rust-foo-1.0".to_string(),
                    subpackage: "main".to_string(),
                    version: "1.2.3".to_string(),
                }],
            )]),
            warnings: vec![legacy_warning(
                "rust-foo-1.0",
                "crate(foo-1.0)",
                "rust-foo-1",
            )],
            skipped: Vec::new(),
            summary: RepoIndexSummary::default(),
        };

        let plan = build_migration_plan(Path::new("/repo/SPECS"), &index, MigrateScope::Legacy, 20)
            .unwrap();
        assert_eq!(plan.summary.providers, 1);
        assert_eq!(plan.providers[0].old_package, "rust-foo-1.0");
        assert_eq!(plan.providers[0].new_package, "rust-foo-1");
        assert_eq!(plan.consumer_rewrites[0].from, "crate(foo-1.0");
        assert_eq!(plan.consumer_rewrites[0].to, "crate(foo-1");
    }

    #[test]
    fn legacy_plan_prefers_warning_capability_over_bare_provides() {
        let index = RepoIndex {
            packages: vec![package_with_provides(
                "rust-ansi-to-tui-8.0",
                "ansi-to-tui",
                "8.0.1",
                &["crate(ansi-to-tui)", "crate(ansi-to-tui-8.0)"],
            )],
            capabilities: BTreeMap::new(),
            warnings: vec![legacy_warning(
                "rust-ansi-to-tui-8.0",
                "crate(ansi-to-tui-8.0)",
                "rust-ansi-to-tui-8",
            )],
            skipped: Vec::new(),
            summary: RepoIndexSummary::default(),
        };

        let plan = build_migration_plan(Path::new("/repo/SPECS"), &index, MigrateScope::Legacy, 20)
            .unwrap();
        assert_eq!(
            plan.providers[0].old_capability_prefix,
            "crate(ansi-to-tui-8.0"
        );
        assert_eq!(plan.consumer_rewrites[0].from, "crate(ansi-to-tui-8.0");
    }

    #[test]
    fn dotted_major_fallback_only_applies_to_positive_integer_major() {
        assert_eq!(
            dotted_major_fallback_capability("crate(memchr-2/std)").as_deref(),
            Some("crate(memchr-2.0/std)")
        );
        assert_eq!(
            dotted_major_fallback_capability("crate(rustversion-1/default)").as_deref(),
            Some("crate(rustversion-1.0/default)")
        );
        assert_eq!(
            dotted_major_fallback_capability("crate(base64-0.22/default)"),
            None
        );
        assert_eq!(dotted_major_fallback_capability("crate(foo-0/std)"), None);
        assert_eq!(
            dotted_major_fallback_capability("crate(im-rc-15/default)").as_deref(),
            Some("crate(im-rc-15.0/default)")
        );
    }

    #[test]
    fn capability_prefix_match_is_exact_or_feature_only() {
        assert!(capability_matches_prefix("crate(foo-1)", "crate(foo-1"));
        assert!(capability_matches_prefix(
            "crate(foo-1/default)",
            "crate(foo-1"
        ));
        assert!(!capability_matches_prefix("crate(foo-10)", "crate(foo-1"));
        assert!(!capability_matches_prefix("crate(foo-1.0)", "crate(foo-1"));
    }

    #[test]
    fn scoped_requires_rewrite_falls_back_only_in_requires_lines() {
        let temp = tempfile::tempdir().unwrap();
        let provider_dir = temp.path().join("rust-aho-corasick-1");
        fs::create_dir_all(&provider_dir).unwrap();
        let spec_path = provider_dir.join("rust-aho-corasick.spec");
        fs::write(
            &spec_path,
            "\
Name: rust-aho-corasick-1
Provides: crate(memchr-2/std) = 2.0.0
Requires: crate(memchr-2/std) >= 2.0.0
Requires: crate(aho-corasick-1/default) = 1.0.0
Requires: crate(%{pkgname}) = %{version}
",
        )
        .unwrap();

        let repo_capabilities = BTreeSet::from(["crate(memchr-2.0/std)".to_string()]);
        let selected_new_prefixes = BTreeSet::from(["crate(aho-corasick-1".to_string()]);
        let result =
            scope_provider_requires(&provider_dir, &repo_capabilities, &selected_new_prefixes)
                .unwrap();

        assert_eq!(result.rewritten, 1);
        assert!(result.unresolved.is_empty());
        let updated = fs::read_to_string(spec_path).unwrap();
        assert!(updated.contains("Provides: crate(memchr-2/std) = 2.0.0"));
        assert!(updated.contains("Requires: crate(memchr-2.0/std) >= 2.0.0"));
        assert!(updated.contains("Requires: crate(aho-corasick-1/default) = 1.0.0"));
        assert!(updated.contains("Requires: crate(%{pkgname}) = %{version}"));
    }

    #[test]
    fn scoped_requires_keeps_dependencies_selected_in_same_batch() {
        let temp = tempfile::tempdir().unwrap();
        let provider_dir = temp.path().join("rust-aho-corasick-1");
        fs::create_dir_all(&provider_dir).unwrap();
        let spec_path = provider_dir.join("rust-aho-corasick.spec");
        fs::write(
            &spec_path,
            "Requires: crate(memchr-2/std) >= 2.0.0\nRequires: crate(base64-0.22/default)\n",
        )
        .unwrap();

        let repo_capabilities = BTreeSet::from([
            "crate(memchr-2.0/std)".to_string(),
            "crate(base64-0.22/default)".to_string(),
        ]);
        let selected_new_prefixes = BTreeSet::from([
            "crate(aho-corasick-1".to_string(),
            "crate(memchr-2".to_string(),
        ]);
        let result =
            scope_provider_requires(&provider_dir, &repo_capabilities, &selected_new_prefixes)
                .unwrap();

        assert_eq!(result.rewritten, 0);
        assert!(result.unresolved.is_empty());
        let updated = fs::read_to_string(spec_path).unwrap();
        assert!(updated.contains("Requires: crate(memchr-2/std)"));
        assert!(updated.contains("Requires: crate(base64-0.22/default)"));
        assert!(!updated.contains("base64-0.22.0"));
    }

    #[test]
    fn scoped_requires_records_unresolved_new_requires() {
        let temp = tempfile::tempdir().unwrap();
        let provider_dir = temp.path().join("rust-foo-1");
        fs::create_dir_all(&provider_dir).unwrap();
        fs::write(
            provider_dir.join("rust-foo.spec"),
            "Requires: crate(missingdep-1/default) >= 1.0.0\n",
        )
        .unwrap();

        let result =
            scope_provider_requires(&provider_dir, &BTreeSet::new(), &BTreeSet::new()).unwrap();

        assert_eq!(result.rewritten, 0);
        assert_eq!(result.unresolved.len(), 1);
        assert_eq!(
            result.unresolved[0].capability,
            "crate(missingdep-1/default)"
        );
    }

    fn write_provider_spec(
        package_root: &Path,
        package: &str,
        crate_name: &str,
        pkgname: &str,
        version: &str,
        extra_lines: &str,
    ) {
        let dir = package_root.join(package);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(format!("{package}.spec")),
            format!(
                "\
%global crate_name {crate_name}
%global full_version {version}
%global pkgname {pkgname}
Name: {package}
Version: {version}
Provides: crate(%{{pkgname}})
{extra_lines}\n"
            ),
        )
        .unwrap();
    }

    fn migration_provider(
        package_root: &Path,
        old: &str,
        new: &str,
        crate_name: &str,
    ) -> MigrationProvider {
        let version = "1.0.0".to_string();
        MigrationProvider {
            old_package: old.to_string(),
            new_package: new.to_string(),
            crate_name: crate_name.to_string(),
            crate_name_hyphen: crate_name.replace('_', "-"),
            version,
            old_capability_prefix: rust_package_capability_prefix(old).unwrap(),
            new_capability_prefix: rust_package_capability_prefix(new).unwrap(),
            old_dir: package_root.join(old).display().to_string(),
            new_dir: package_root.join(new).display().to_string(),
            reason: "legacy-compat-name".to_string(),
        }
    }

    fn migration_plan(package_root: &Path, providers: Vec<MigrationProvider>) -> MigrationPlan {
        let consumer_rewrites = providers
            .iter()
            .map(|provider| ConsumerRewrite {
                from: provider.old_capability_prefix.clone(),
                to: provider.new_capability_prefix.clone(),
            })
            .collect::<Vec<_>>();
        MigrationPlan {
            package_root: package_root.display().to_string(),
            scope: MigrateScope::Legacy,
            summary: MigrationPlanSummary {
                providers: providers.len(),
                rewrites: consumer_rewrites.len(),
                skipped: 0,
            },
            providers,
            consumer_rewrites,
            skipped: Vec::new(),
        }
    }

    fn write_plan(path: &Path, plan: &MigrationPlan) {
        fs::write(path, serde_json::to_string_pretty(plan).unwrap()).unwrap();
    }

    fn apply_options(
        plan: &Path,
        package_root: &Path,
        staging: &Path,
        apply_safe_subset: bool,
    ) -> MigrateApplyOptions {
        MigrateApplyOptions {
            plan: plan.to_path_buf(),
            package_root: package_root.to_path_buf(),
            staging: staging.to_path_buf(),
            yes: true,
            verify_apps: Vec::new(),
            skip_package_generation: true,
            keep_old: false,
            allow_prerelease: false,
            apply_safe_subset,
        }
    }

    #[test]
    fn migrate_apply_preflight_blocks_unsafe_provider_without_modifying_package_root() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("SPECS");
        let staging = temp.path().join("staging");
        write_provider_spec(
            &package_root,
            "rust-foo-1.0",
            "foo",
            "foo-1.0",
            "1.0.0",
            "Requires: crate(missing-1/default) >= 1.0.0",
        );
        let plan = migration_plan(
            &package_root,
            vec![migration_provider(
                &package_root,
                "rust-foo-1.0",
                "rust-foo-1",
                "foo",
            )],
        );
        let plan_path = temp.path().join("plan.json");
        write_plan(&plan_path, &plan);

        let (exit_code, report) =
            execute_migrate_apply(apply_options(&plan_path, &package_root, &staging, false))
                .unwrap();

        assert_eq!(exit_code, 1);
        assert!(report.preflight);
        assert_eq!(report.providers_regenerated, 0);
        assert_eq!(report.unresolved_new_requires.len(), 1);
        assert_eq!(report.unsafe_providers[0].old_package, "rust-foo-1.0");
        assert!(package_root.join("rust-foo-1.0").exists());
        assert!(!package_root.join("rust-foo-1").exists());
    }

    #[test]
    fn migrate_apply_safe_subset_applies_only_safe_providers() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("SPECS");
        let staging = temp.path().join("staging");
        write_provider_spec(
            &package_root,
            "rust-foo-1.0",
            "foo",
            "foo-1.0",
            "1.0.0",
            "Requires: crate(missing-1/default) >= 1.0.0",
        );
        write_provider_spec(&package_root, "rust-bar-1.0", "bar", "bar-1.0", "1.0.0", "");
        let consumer_dir = package_root.join("consumer");
        fs::create_dir_all(&consumer_dir).unwrap();
        let consumer_spec = consumer_dir.join("consumer.spec");
        fs::write(
            &consumer_spec,
            "Name: consumer\nVersion: 1.0\nRequires: crate(foo-1.0/default) >= 1.0.0\nRequires: crate(bar-1.0/default) >= 1.0.0\n",
        )
        .unwrap();
        let plan = migration_plan(
            &package_root,
            vec![
                migration_provider(&package_root, "rust-foo-1.0", "rust-foo-1", "foo"),
                migration_provider(&package_root, "rust-bar-1.0", "rust-bar-1", "bar"),
            ],
        );
        let plan_path = temp.path().join("plan.json");
        write_plan(&plan_path, &plan);

        let (exit_code, report) =
            execute_migrate_apply(apply_options(&plan_path, &package_root, &staging, true))
                .unwrap();

        assert_eq!(exit_code, 0);
        assert_eq!(report.providers_regenerated, 1);
        assert_eq!(report.skipped_unsafe_providers.len(), 1);
        assert_eq!(
            report.skipped_unsafe_providers[0].old_package,
            "rust-foo-1.0"
        );
        assert!(package_root.join("rust-foo-1.0").exists());
        assert!(!package_root.join("rust-foo-1").exists());
        assert!(!package_root.join("rust-bar-1.0").exists());
        assert!(package_root.join("rust-bar-1").exists());
        let consumer = fs::read_to_string(consumer_spec).unwrap();
        assert!(consumer.contains("crate(foo-1.0/default)"));
        assert!(consumer.contains("crate(bar-1/default)"));
    }

    #[test]
    fn migrate_apply_preflight_uses_scoped_dotted_fallback() {
        let temp = tempfile::tempdir().unwrap();
        let package_root = temp.path().join("SPECS");
        let staging = temp.path().join("staging");
        write_provider_spec(
            &package_root,
            "rust-foo-1.0",
            "foo",
            "foo-1.0",
            "1.0.0",
            "Requires: crate(memchr-2/std) >= 2.0.0",
        );
        write_provider_spec(
            &package_root,
            "rust-memchr-2.0",
            "memchr",
            "memchr-2.0",
            "2.7.5",
            "Provides: crate(memchr-2.0/std)",
        );
        let plan = migration_plan(
            &package_root,
            vec![migration_provider(
                &package_root,
                "rust-foo-1.0",
                "rust-foo-1",
                "foo",
            )],
        );
        let plan_path = temp.path().join("plan.json");
        write_plan(&plan_path, &plan);

        let (exit_code, report) =
            execute_migrate_apply(apply_options(&plan_path, &package_root, &staging, false))
                .unwrap();

        assert_eq!(exit_code, 0);
        assert!(report.unresolved_new_requires.is_empty());
        assert_eq!(report.scoped_requires_rewritten, 1);
        let new_spec =
            fs::read_to_string(package_root.join("rust-foo-1/rust-foo-1.0.spec")).unwrap();
        assert!(new_spec.contains("Requires: crate(memchr-2.0/std) >= 2.0.0"));
    }
}
