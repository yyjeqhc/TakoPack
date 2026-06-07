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
    pub providers_regenerated: usize,
    pub old_dirs_removed: usize,
    pub consumer_files_touched: usize,
    pub consumer_rewrite_occurrences: usize,
    pub old_prefix_remaining_count: usize,
    pub verify: Vec<MigrationVerifyReport>,
    pub git_diff_stat: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationVerifyReport {
    pub cargo_toml: String,
    pub repo_plan_summary: crate::repo_check::RepoPlanSummary,
    pub repo_check_summary: crate::repo_check::RepoCheckSummary,
    pub buildreqs_summary: crate::repo_check::BuildReqsSummary,
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
            providers_regenerated: 0,
            old_dirs_removed: 0,
            consumer_files_touched: 0,
            consumer_rewrite_occurrences: 0,
            old_prefix_remaining_count: 0,
            verify: Vec::new(),
            git_diff_stat: String::new(),
            notes,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(0);
    }

    ensure_apply_is_allowed(&plan, options.allow_prerelease)?;
    fs::create_dir_all(&options.staging)
        .with_context(|| format!("failed to create {}", options.staging.display()))?;

    let mut providers_regenerated = 0usize;
    let mut old_dirs_removed = 0usize;
    for provider in &plan.providers {
        let new_dir = package_root.join(&provider.new_package);
        let old_dir = package_root.join(&provider.old_package);

        if new_dir.exists() {
            fs::remove_dir_all(&new_dir)
                .with_context(|| format!("failed to remove {}", new_dir.display()))?;
        }

        if options.skip_package_generation {
            copy_provider_skeleton(provider, &old_dir, &new_dir)?;
        } else {
            let staged_dir = generate_provider(provider, &options.staging)?;
            copy_dir_replace(&staged_dir, &new_dir)?;
        }
        providers_regenerated += 1;

        if !options.keep_old && old_dir.exists() {
            fs::remove_dir_all(&old_dir)
                .with_context(|| format!("failed to remove {}", old_dir.display()))?;
            old_dirs_removed += 1;
        }
    }

    let rewrite_result = rewrite_consumers(&package_root, &plan.consumer_rewrites)?;
    let remaining = count_old_prefixes(&package_root, &plan.consumer_rewrites)?;
    let index = build_repo_index_with_options(&package_root, RepoIndexOptions::default())?;
    let verify = verify_apps(&options.verify_apps, &index)?;
    let git_diff_stat = git_diff_stat(&package_root).unwrap_or_default();

    if remaining > 0 {
        notes.push(format!(
            "{remaining} selected old capability prefix references remain"
        ));
    }
    if options.skip_package_generation {
        notes.push("provider generation skipped; copied/replaced local skeletons".to_string());
    }

    let report = MigrationApplyReport {
        plan: display_path(&options.plan),
        package_root: package_root.display().to_string(),
        dry_run: false,
        providers_regenerated,
        old_dirs_removed,
        consumer_files_touched: rewrite_result.files_touched,
        consumer_rewrite_occurrences: rewrite_result.occurrences,
        old_prefix_remaining_count: remaining,
        verify,
        git_diff_stat,
        notes,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(0)
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
}
