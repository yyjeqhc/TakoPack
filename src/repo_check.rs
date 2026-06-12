use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use toml::Value;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoIndex {
    pub packages: Vec<IndexedPackage>,
    pub capabilities: BTreeMap<String, Vec<CapabilityProvider>>,
    pub warnings: Vec<RepoWarning>,
    #[serde(default)]
    pub skipped: Vec<SkippedPackage>,
    #[serde(default)]
    pub summary: RepoIndexSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkippedPackage {
    pub name: String,
    pub path: String,
    pub reason: String,
    pub has_spec: bool,
    pub has_cargo_toml: bool,
    pub has_crate_capabilities: bool,
    pub is_rust_candidate: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoIndexSummary {
    pub scanned_specs: usize,
    pub indexed_packages: usize,
    pub capabilities: usize,
    pub warnings: usize,
    pub ignored_non_rust_specs: usize,
    pub skipped_rust_candidates: usize,
    pub rust_candidates_missing_cargo_toml: usize,
    pub rust_candidates_missing_capabilities: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedPackage {
    pub rpm_name: String,
    pub version: String,
    pub crate_name: String,
    pub pkgname: String,
    pub spec_path: String,
    pub provides: Vec<ProvideRecord>,
    pub requires: Vec<RequireRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvideRecord {
    pub cap: String,
    pub version: String,
    pub subpackage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequireRecord {
    pub cap: String,
    pub op: Option<String>,
    pub version: Option<String>,
    pub subpackage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProvider {
    pub rpm_name: String,
    pub subpackage: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoWarning {
    #[serde(rename = "type")]
    pub warning_type: String,
    pub rpm_name: String,
    pub subpackage: String,
    pub cap: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalized_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requirement: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoCheckResult {
    pub cargo_toml: String,
    pub ok: Vec<CheckRecord>,
    pub missing: Vec<CheckRecord>,
    pub conflicts: Vec<CheckRecord>,
    pub transitive: Vec<CheckRecord>,
    pub transitive_ok: Vec<CheckRecord>,
    pub transitive_missing: Vec<CheckRecord>,
    pub transitive_conflicts: Vec<CheckRecord>,
    pub warnings: Vec<RepoWarning>,
    pub summary: RepoCheckSummary,
    pub human_blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoCheckSummary {
    pub ok: usize,
    pub missing: usize,
    pub conflicts: usize,
    pub transitive_ok: usize,
    pub transitive_missing: usize,
    pub transitive_conflicts: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPlanResult {
    pub cargo_toml: String,
    pub need_add: Vec<NeedAddAction>,
    pub need_update: Vec<NeedUpdateAction>,
    pub duplicates: Vec<DuplicateAction>,
    pub unsupported: Vec<UnsupportedAction>,
    pub policy_warnings: Vec<RepoWarning>,
    pub summary: RepoPlanSummary,
    pub repo_check_summary: RepoCheckSummary,
    pub warnings: Vec<RepoWarning>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoPlanSummary {
    pub need_add: usize,
    pub need_update: usize,
    pub duplicates: usize,
    pub unsupported: usize,
}

#[derive(Debug, Clone)]
pub struct RepoPlanOptions {
    pub check_transitive: bool,
    pub json: bool,
    pub include_global_warnings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHealthReport {
    pub index: String,
    pub rename: Vec<RenameAction>,
    pub dedupe: Vec<DedupeAction>,
    pub remove_prerelease: Vec<RemovePrereleaseAction>,
    pub exact_version_packages: Vec<ExactVersionPackageAction>,
    pub duplicates: Vec<DuplicateAction>,
    pub skipped: Vec<SkippedPackage>,
    pub summary: RepoHealthSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameAction {
    pub current: String,
    pub target: String,
    pub reason: String,
    pub capability_current: String,
    pub capability_target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupeAction {
    pub slot: String,
    pub keep: String,
    pub remove: Vec<String>,
    pub reason: String,
    pub manual_review: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemovePrereleaseAction {
    pub package: String,
    pub suggested_action: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExactVersionPackageAction {
    pub package: String,
    pub suggested_slot: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoHealthSummary {
    pub rename: usize,
    pub dedupe: usize,
    pub remove_prerelease: usize,
    pub exact_version_packages: usize,
    pub duplicates: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum BuildReqsKind {
    Crate,
    App,
}

#[derive(Debug, Clone)]
pub struct BuildReqsOptions {
    pub kind: BuildReqsKind,
    pub include_build: bool,
    pub include_dev: bool,
    pub json: bool,
    pub check: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReqsResult {
    pub cargo_toml: String,
    pub kind: BuildReqsKind,
    pub include_build: bool,
    pub include_dev: bool,
    pub buildrequires: Vec<BuildRequiresRecord>,
    pub missing: Vec<CheckRecord>,
    pub conflicts: Vec<CheckRecord>,
    pub warnings: Vec<RepoWarning>,
    pub summary: BuildReqsSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRequiresRecord {
    pub section: String,
    pub dependency: String,
    pub package: String,
    pub capability: String,
    pub requirement: Option<String>,
    pub feature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildReqsSummary {
    pub buildrequires: usize,
    pub missing: usize,
    pub conflicts: usize,
    pub warnings: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeedAddAction {
    pub capability: String,
    pub suggested_package: String,
    pub reason: String,
    pub requirement: Option<String>,
    pub required_by: Vec<String>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeedUpdateAction {
    pub capability: String,
    pub package: String,
    pub current_version: String,
    pub required: Option<String>,
    pub reason: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateAction {
    pub capability: String,
    pub providers: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnsupportedAction {
    #[serde(rename = "type")]
    pub action_type: String,
    pub capability: String,
    pub requirement: Option<String>,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuditReport {
    pub ruyispec_dir: String,
    pub package_root: String,
    pub index: String,
    pub apps: Vec<AppAuditRecord>,
    pub skipped: Vec<AppAuditSkipped>,
    pub summary: AppAuditSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuditRecord {
    pub name: String,
    pub path: String,
    pub cargo_toml: String,
    pub status: String,
    pub summary: RepoPlanSummary,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppAuditSkipped {
    pub name: String,
    pub path: String,
    pub reason: String,
    pub has_spec: bool,
    pub has_cargo_toml: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppAuditSummary {
    pub total: usize,
    pub green: usize,
    pub yellow: usize,
    pub orange: usize,
    pub red: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckRecord {
    pub dependency: String,
    pub capability: String,
    pub status: String,
    pub requirement: Option<String>,
    pub provider: Option<CapabilityProvider>,
    pub chain: Vec<String>,
    pub message: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RepoCheckOptions {
    pub check_transitive: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RepoIndexOptions {
    pub include_all_specs: bool,
}

#[derive(Debug, Clone)]
struct DepRequest {
    alias: String,
    package_name: String,
    repo_pkgname: String,
    required_version: Vec<u64>,
    default_features: bool,
    features: Vec<String>,
    warnings: Vec<RepoWarning>,
}

#[derive(Debug, Clone)]
struct BuildReqRequest {
    section: String,
    alias: String,
    package_name: String,
    repo_pkgname: String,
    version_requirement: String,
    required_version: Vec<u64>,
    default_features: bool,
    features: Vec<String>,
    warnings: Vec<RepoWarning>,
}

#[derive(Debug, Clone)]
struct Resolution {
    provider: Option<CapabilityProvider>,
    status: &'static str,
    message: Option<String>,
}

struct SpecRegexes {
    global: Regex,
    name: Regex,
    version: Regex,
    package: Regex,
    description: Regex,
    files: Regex,
    provides: Regex,
    requires: Regex,
    cap: Regex,
    req_cap: Regex,
    cap_with_constraint: Regex,
    macro_ref: Regex,
}

fn spec_regexes() -> &'static SpecRegexes {
    static REGEXES: OnceLock<SpecRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| SpecRegexes {
        global: Regex::new(r"^%global\s+(\S+)\s+(.*)$").unwrap(),
        name: Regex::new(r"^Name:\s*(\S+)").unwrap(),
        version: Regex::new(r"^Version:\s*(\S+)").unwrap(),
        package: Regex::new(r"^%package\b(.*)$").unwrap(),
        description: Regex::new(r"^%description\b").unwrap(),
        files: Regex::new(r"^%files\b").unwrap(),
        provides: Regex::new(r"^Provides:\s*(.*)$").unwrap(),
        requires: Regex::new(r"^Requires:\s*(.*)$").unwrap(),
        cap: Regex::new(r"crate\(([^)]+)\)").unwrap(),
        req_cap: Regex::new(r"^crate\(([^)]+)\)(?:\s*(>=|=|<=|>|<)\s*([^\s#]+))?").unwrap(),
        cap_with_constraint: Regex::new(r"crate\([^)]+\)\s*(>=|=|<=|>|<)\s*[^\s#]+").unwrap(),
        macro_ref: Regex::new(r"%\{([^}]+)\}").unwrap(),
    })
}

fn expand_macros(text: &str, macros: &HashMap<String, String>) -> String {
    let regexes = spec_regexes();
    let mut result = text.to_string();
    for _ in 0..10 {
        let updated = regexes
            .macro_ref
            .replace_all(&result, |captures: &regex::Captures<'_>| {
                macros
                    .get(&captures[1])
                    .cloned()
                    .unwrap_or_else(|| captures[0].to_string())
            })
            .into_owned();
        if updated == result {
            break;
        }
        result = updated;
    }
    result
}

pub fn build_repo_index(spec_root: &Path) -> Result<RepoIndex> {
    build_repo_index_with_options(spec_root, RepoIndexOptions::default())
}

pub fn build_repo_index_with_options(
    spec_root: &Path,
    options: RepoIndexOptions,
) -> Result<RepoIndex> {
    if !spec_root.is_dir() {
        bail!(
            "spec repo directory does not exist: {}",
            spec_root.display()
        );
    }

    let mut packages = Vec::new();
    let mut capabilities: BTreeMap<String, Vec<CapabilityProvider>> = BTreeMap::new();
    let mut warnings = Vec::new();
    let mut skipped = Vec::new();
    let mut summary = RepoIndexSummary::default();

    let mut spec_paths = Vec::new();
    for entry in WalkDir::new(spec_root) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "spec")
        {
            spec_paths.push(entry.path().to_path_buf());
        }
    }
    spec_paths.sort();
    summary.scanned_specs = spec_paths.len();

    for spec_path in spec_paths {
        let (mut package, mut package_warnings) = parse_spec(&spec_path)?;
        let spec_dir = spec_path.parent().unwrap_or_else(|| Path::new("."));
        let dir_name = spec_dir
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let has_cargo_toml = spec_dir.join("Cargo.toml").is_file();
        let has_crate_capabilities = !package.provides.is_empty() || !package.requires.is_empty();
        let has_crate_syntax = has_crate_capabilities
            || package_warnings
                .iter()
                .any(|warning| warning.warning_type == "unsupported-requires");
        let has_crate_macros =
            !package.crate_name.is_empty() || pkgname_looks_like_crate_compat(&package.pkgname);
        let rust_named = package.rpm_name.starts_with("rust-") || dir_name.starts_with("rust-");
        let is_rust_candidate =
            rust_named || has_crate_syntax || has_crate_macros || has_cargo_toml;

        if !options.include_all_specs && !is_rust_candidate {
            summary.ignored_non_rust_specs += 1;
            continue;
        }

        let new_takopack_spec = !package.crate_name.is_empty()
            && !package.pkgname.is_empty()
            && !package.version.is_empty();
        let inferred_from_cargo =
            rust_named && infer_package_identity_from_cargo_toml(&mut package, spec_dir);
        let indexable = options.include_all_specs
            || has_crate_syntax
            || new_takopack_spec
            || inferred_from_cargo;

        if !indexable {
            let reason = if !has_cargo_toml {
                summary.rust_candidates_missing_cargo_toml += 1;
                "missing-cargo-toml"
            } else {
                summary.rust_candidates_missing_capabilities += 1;
                "missing-capabilities"
            };
            skipped.push(SkippedPackage {
                name: skipped_package_name(&package, dir_name),
                path: display_path(&spec_path),
                reason: reason.to_string(),
                has_spec: true,
                has_cargo_toml,
                has_crate_capabilities,
                is_rust_candidate,
            });
            warnings.extend(package_warnings);
            continue;
        }

        if is_rust_candidate {
            add_package_policy_warning(&package, dir_name, &mut package_warnings);
        }

        for provide in &package.provides {
            capabilities
                .entry(provide.cap.clone())
                .or_default()
                .push(CapabilityProvider {
                    rpm_name: package.rpm_name.clone(),
                    subpackage: provide.subpackage.clone(),
                    version: provide.version.clone(),
                });
        }
        warnings.extend(package_warnings);
        packages.push(package);
    }

    for (cap, providers) in &capabilities {
        let unique: BTreeSet<_> = providers
            .iter()
            .map(|provider| (provider.rpm_name.clone(), provider.subpackage.clone()))
            .collect();
        if unique.len() > 1 {
            warnings.push(RepoWarning {
                warning_type: "duplicate-provider".to_string(),
                rpm_name: unique
                    .iter()
                    .map(|(rpm_name, _)| rpm_name.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
                subpackage: unique
                    .iter()
                    .map(|(_, subpackage)| subpackage.clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
                cap: cap.clone(),
                normalized_version: None,
                requirement: None,
                line: None,
                expected: None,
                message: "multiple packages/subpackages provide the same crate capability"
                    .to_string(),
            });
        }
    }

    summary.indexed_packages = packages.len();
    summary.capabilities = capabilities.len();
    summary.warnings = warnings.len();
    summary.skipped_rust_candidates = skipped.len();

    Ok(RepoIndex {
        packages,
        capabilities,
        warnings,
        skipped,
        summary,
    })
}

fn infer_package_identity_from_cargo_toml(package: &mut IndexedPackage, spec_dir: &Path) -> bool {
    let Some(crate_name) = cargo_package_name(&spec_dir.join("Cargo.toml")) else {
        return false;
    };
    if package.crate_name.is_empty() {
        package.crate_name = crate_name;
    }
    if package.pkgname.is_empty() {
        package.pkgname =
            repo_pkgname_for_dependency(&package.crate_name, &parse_version(&package.version));
    }
    !package.crate_name.is_empty() && !package.pkgname.is_empty() && !package.version.is_empty()
}

fn cargo_package_name(cargo_toml: &Path) -> Option<String> {
    let content = fs::read_to_string(cargo_toml).ok()?;
    let manifest: Value = toml::from_str(&content).ok()?;
    manifest
        .get("package")
        .and_then(Value::as_table)?
        .get("name")
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn add_package_policy_warning(
    package: &IndexedPackage,
    dir_name: &str,
    warnings: &mut Vec<RepoWarning>,
) {
    let Some(expected) = expected_rust_package_name(&package.crate_name, &package.version) else {
        return;
    };
    let name_mismatch = package.rpm_name != expected;
    let dir_mismatch = !dir_name.is_empty() && dir_name != expected;
    if !name_mismatch && !dir_mismatch {
        return;
    }

    let warning_type = package_policy_warning_type(package);
    warnings.push(RepoWarning {
        warning_type: warning_type.to_string(),
        rpm_name: package.rpm_name.clone(),
        subpackage: "main".to_string(),
        cap: package_capability(&package.pkgname, None),
        normalized_version: None,
        requirement: None,
        line: None,
        expected: Some(expected),
        message: package_policy_warning_message(warning_type).to_string(),
    });
}

fn package_policy_warning_type(package: &IndexedPackage) -> &'static str {
    if has_prerelease_package_version_marker(package) {
        "prerelease-version"
    } else if exact_version_package_name(&package.rpm_name, &package.crate_name, &package.version) {
        "exact-version-package"
    } else if legacy_compat_name(&package.rpm_name, &package.crate_name, &package.version) {
        "legacy-compat-name"
    } else {
        "naming-mismatch"
    }
}

fn package_policy_warning_message(warning_type: &str) -> &'static str {
    match warning_type {
        "legacy-compat-name" => {
            "Rust crate package uses an old dotted compat package name; prefer rust-<crate>-<compat-branch>"
        }
        "exact-version-package" => {
            "Rust crate package appears to use an exact-version package name; keep exact exceptions out of ordinary compat capability"
        }
        "prerelease-version" => {
            "Pre-release Rust crate package should not enter the ordinary compat branch by default"
        }
        _ => "Rust crate package name should follow rust-<crate>-<compat-branch>",
    }
}

fn expected_rust_package_name(crate_name: &str, version: &str) -> Option<String> {
    if crate_name.is_empty() {
        return None;
    }
    let branch = compat_branch(&parse_version(version))?;
    Some(format!("rust-{}-{branch}", crate_name.replace('_', "-")))
}

fn legacy_compat_name(rpm_name: &str, crate_name: &str, version: &str) -> bool {
    let parts = parse_version(version);
    if parts.len() < 2 || parts[0] == 0 {
        return false;
    }
    let legacy_actual_minor = format!(
        "rust-{}-{}.{}",
        crate_name.replace('_', "-"),
        parts[0],
        parts[1]
    );
    let legacy_major_zero = format!("rust-{}-{}.0", crate_name.replace('_', "-"), parts[0]);
    rpm_name == legacy_actual_minor || rpm_name == legacy_major_zero
}

fn exact_version_package_name(rpm_name: &str, crate_name: &str, version: &str) -> bool {
    let parts = parse_version(version);
    if parts.len() < 3 {
        return false;
    }
    let exact = format!(
        "rust-{}-{}",
        crate_name.replace('_', "-"),
        parts
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    );
    rpm_name == exact
}

fn has_prerelease_package_version_marker(package: &IndexedPackage) -> bool {
    if has_prerelease_version_marker(&package.version) {
        return true;
    }
    let package_prefix = format!("rust-{}-", package.crate_name.replace('_', "-"));
    package
        .rpm_name
        .strip_prefix(&package_prefix)
        .is_some_and(has_prerelease_version_marker)
}

fn has_prerelease_version_marker(version: &str) -> bool {
    let Some((release, suffix)) = version.split_once('-') else {
        return false;
    };
    if parse_version(release).is_empty() {
        return false;
    }
    suffix
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|segment| matches!(segment, "rc" | "pre" | "alpha" | "beta"))
}

fn pkgname_looks_like_crate_compat(pkgname: &str) -> bool {
    let Some((_, branch)) = pkgname.rsplit_once('-') else {
        return false;
    };
    let parts = parse_version(branch);
    !parts.is_empty()
}

fn skipped_package_name(package: &IndexedPackage, dir_name: &str) -> String {
    if !package.rpm_name.is_empty() {
        package.rpm_name.clone()
    } else {
        dir_name.to_string()
    }
}

fn parse_spec(path: &Path) -> Result<(IndexedPackage, Vec<RepoWarning>)> {
    let regexes = spec_regexes();
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read spec file {}", path.display()))?;
    let mut rpm_name = String::new();
    let mut version = String::new();
    let mut crate_name = String::new();
    let mut full_version = String::new();
    let mut pkgname = String::new();
    let mut macros = HashMap::new();
    let mut provides = Vec::new();
    let mut requires = Vec::new();
    let mut warnings = Vec::new();
    let mut current_subpackage = "main".to_string();

    for (index, raw_line) in content.lines().enumerate() {
        let line_no = index + 1;
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }

        if let Some(captures) = regexes.global.captures(stripped) {
            let key = captures[1].to_string();
            let value = expand_macros(captures[2].trim(), &macros);
            macros.insert(key.clone(), value.clone());
            match key.as_str() {
                "crate_name" => crate_name = value,
                "full_version" => full_version = value,
                "pkgname" => pkgname = value,
                _ => {}
            }
            continue;
        }

        if let Some(captures) = regexes.name.captures(stripped) {
            rpm_name = captures[1].to_string();
            macros.entry("name".to_string()).or_insert(rpm_name.clone());
            continue;
        }

        if let Some(captures) = regexes.version.captures(stripped) {
            version = captures[1].to_string();
            macros
                .entry("version".to_string())
                .or_insert(version.clone());
            if full_version.is_empty() {
                full_version = version.clone();
            }
            continue;
        }

        if regexes.package.is_match(stripped) {
            let package_line = expand_macros(stripped, &macros);
            let package_name = package_line
                .split_once("-n")
                .map(|(_, rest)| rest.trim().to_string())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| rpm_name.clone());
            current_subpackage = if package_name.is_empty() {
                "main".to_string()
            } else {
                package_name
            };
            continue;
        }

        if regexes.description.is_match(stripped) || regexes.files.is_match(stripped) {
            current_subpackage = "main".to_string();
            continue;
        }

        if let Some(captures) = regexes.provides.captures(stripped) {
            let payload = expand_macros(captures[1].trim(), &macros);
            if let Some(cap_captures) = regexes.cap.captures(&payload) {
                let cap = format!("crate({})", &cap_captures[1]);
                if !regexes.cap_with_constraint.is_match(&payload) {
                    warnings.push(RepoWarning {
                        warning_type: "unversioned-provides".to_string(),
                        rpm_name: rpm_name.clone(),
                        subpackage: current_subpackage.clone(),
                        cap: cap.clone(),
                        normalized_version: Some(version.clone()),
                        requirement: None,
                        line: Some(line_no),
                        expected: None,
                        message: format!(
                            "repo-index normalized this Provides to version {}, but RPM metadata may remain unversioned",
                            version
                        ),
                    });
                }
                provides.push(ProvideRecord {
                    cap,
                    version: version.clone(),
                    subpackage: current_subpackage.clone(),
                });
            }
            continue;
        }

        if let Some(captures) = regexes.requires.captures(stripped) {
            let payload = expand_macros(captures[1].trim(), &macros);
            if let Some(cap_captures) = regexes.req_cap.captures(&payload) {
                let op = cap_captures.get(2).map(|m| m.as_str().to_string());
                let req_version = cap_captures.get(3).map(|m| m.as_str().to_string());
                let cap = format!("crate({})", &cap_captures[1]);
                if op.is_none() && req_version.is_none() {
                    warnings.push(RepoWarning {
                        warning_type: "unversioned-requires".to_string(),
                        rpm_name: rpm_name.clone(),
                        subpackage: current_subpackage.clone(),
                        cap: cap.clone(),
                        normalized_version: None,
                        requirement: Some(payload.clone()),
                        line: Some(line_no),
                        expected: None,
                        message: "repo-index kept this Requires without a version constraint; RPM metadata may differ".to_string(),
                    });
                }
                requires.push(RequireRecord {
                    cap,
                    op,
                    version: req_version,
                    subpackage: current_subpackage.clone(),
                });
            } else if regexes.cap.is_match(&payload) {
                warnings.push(RepoWarning {
                    warning_type: "unsupported-requires".to_string(),
                    rpm_name: rpm_name.clone(),
                    subpackage: current_subpackage.clone(),
                    cap: String::new(),
                    normalized_version: None,
                    requirement: Some(payload),
                    line: Some(line_no),
                    expected: None,
                    message: "repo-index does not parse RPM rich dependency syntax in Requires"
                        .to_string(),
                });
            }
        }
    }

    if rpm_name.is_empty() || version.is_empty() {
        bail!(
            "failed to parse required Name/Version from {}",
            path.display()
        );
    }

    Ok((
        IndexedPackage {
            rpm_name,
            version,
            crate_name,
            pkgname,
            spec_path: display_path(path),
            provides,
            requires,
        },
        warnings,
    ))
}

pub fn write_repo_index(spec_root: &Path, output: &Path) -> Result<()> {
    write_repo_index_with_options(spec_root, output, RepoIndexOptions::default())
}

pub fn write_repo_index_with_options(
    spec_root: &Path,
    output: &Path,
    options: RepoIndexOptions,
) -> Result<()> {
    let index = build_repo_index_with_options(spec_root, options)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&index)?;
    fs::write(output, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", output.display()))?;
    println!("Repo index: {}", output.display());
    println!("package_root: {}", spec_root.display());
    println!("scanned_specs: {}", index.summary.scanned_specs);
    println!("indexed_packages: {}", index.summary.indexed_packages);
    println!("capabilities: {}", index.summary.capabilities);
    println!("warnings: {}", index.summary.warnings);
    println!(
        "ignored_non_rust_specs: {}",
        index.summary.ignored_non_rust_specs
    );
    println!(
        "skipped_rust_candidates: {}",
        index.summary.skipped_rust_candidates
    );
    Ok(())
}

pub fn run_repo_check(
    cargo_toml: &Path,
    index_path: &Path,
    options: RepoCheckOptions,
) -> Result<i32> {
    let index_content = fs::read_to_string(index_path)
        .with_context(|| format!("failed to read {}", index_path.display()))?;
    let index: RepoIndex = serde_json::from_str(&index_content)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;
    let result = check_cargo_toml(cargo_toml, &index, options.check_transitive)?;

    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_human_result(&result);
    }

    let summary = &result.summary;
    if summary.missing > 0
        || summary.conflicts > 0
        || summary.transitive_missing > 0
        || summary.transitive_conflicts > 0
    {
        Ok(1)
    } else {
        Ok(0)
    }
}

pub fn run_repo_plan(
    cargo_toml: &Path,
    index_path: &Path,
    options: RepoPlanOptions,
) -> Result<i32> {
    let index_content = fs::read_to_string(index_path)
        .with_context(|| format!("failed to read {}", index_path.display()))?;
    let index: RepoIndex = serde_json::from_str(&index_content)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;
    let result = build_repo_plan_with_options(cargo_toml, &index, &options)?;

    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_human_plan(&result);
    }

    Ok(0)
}

pub fn run_repo_health(index_path: &Path, json: bool) -> Result<i32> {
    let index_content = fs::read_to_string(index_path)
        .with_context(|| format!("failed to read {}", index_path.display()))?;
    let index: RepoIndex = serde_json::from_str(&index_content)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;
    let report = build_repo_health_report(index_path, &index);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_repo_health(&report);
    }

    Ok(0)
}

pub fn build_repo_health_report(index_path: &Path, index: &RepoIndex) -> RepoHealthReport {
    let mut rename = Vec::new();
    let mut exact_version_packages = Vec::new();
    let mut remove_prerelease = Vec::new();
    let mut duplicates = Vec::new();
    let packages_by_name: BTreeMap<_, _> = index
        .packages
        .iter()
        .map(|package| (package.rpm_name.as_str(), package))
        .collect();

    for warning in &index.warnings {
        match warning.warning_type.as_str() {
            "legacy-compat-name" => {
                let target = warning
                    .expected
                    .clone()
                    .unwrap_or_else(|| warning.rpm_name.clone());
                let capability_current = packages_by_name
                    .get(warning.rpm_name.as_str())
                    .and_then(|package| main_package_capability(package))
                    .unwrap_or_else(|| {
                        if warning.cap.is_empty() {
                            capability_from_rust_package_name(&warning.rpm_name)
                                .unwrap_or_else(|| warning.cap.clone())
                        } else {
                            warning.cap.clone()
                        }
                    });
                let capability_target = capability_from_rust_package_name(&target)
                    .unwrap_or_else(|| warning.cap.clone());
                rename.push(RenameAction {
                    current: warning.rpm_name.clone(),
                    target,
                    reason: "legacy compat name".to_string(),
                    capability_current,
                    capability_target,
                });
            }
            "exact-version-package" => {
                exact_version_packages.push(ExactVersionPackageAction {
                    package: warning.rpm_name.clone(),
                    suggested_slot: warning
                        .expected
                        .clone()
                        .unwrap_or_else(|| warning.rpm_name.clone()),
                    reason: "exact version package in ordinary repo".to_string(),
                });
            }
            "prerelease-version" => {
                remove_prerelease.push(RemovePrereleaseAction {
                    package: warning.rpm_name.clone(),
                    suggested_action: "remove-or-exact-exception".to_string(),
                    reason: "pre-release crate should not enter ordinary compat slot".to_string(),
                });
            }
            "duplicate-provider" => {
                duplicates.push(DuplicateAction {
                    capability: warning.cap.clone(),
                    providers: warning.rpm_name.clone(),
                    reason: "multiple providers for same capability".to_string(),
                });
            }
            _ => {}
        }
    }

    rename.sort_by(|a, b| a.current.cmp(&b.current));
    exact_version_packages.sort_by(|a, b| a.package.cmp(&b.package));
    remove_prerelease.sort_by(|a, b| a.package.cmp(&b.package));
    duplicates.sort_by(|a, b| a.capability.cmp(&b.capability));
    duplicates.dedup_by(|a, b| a.capability == b.capability);

    let mut dedupe = build_dedupe_actions(index);
    dedupe.sort_by(|a, b| a.slot.cmp(&b.slot));

    RepoHealthReport {
        index: display_path(index_path),
        summary: RepoHealthSummary {
            rename: rename.len(),
            dedupe: dedupe.len(),
            remove_prerelease: remove_prerelease.len(),
            exact_version_packages: exact_version_packages.len(),
            duplicates: duplicates.len(),
        },
        rename,
        dedupe,
        remove_prerelease,
        exact_version_packages,
        duplicates,
        skipped: index.skipped.clone(),
    }
}

fn build_dedupe_actions(index: &RepoIndex) -> Vec<DedupeAction> {
    let mut by_slot: BTreeMap<String, Vec<&IndexedPackage>> = BTreeMap::new();
    for package in &index.packages {
        let Some(slot) = expected_rust_package_name(&package.crate_name, &package.version) else {
            continue;
        };
        by_slot.entry(slot).or_default().push(package);
    }

    let mut actions = Vec::new();
    for (slot, packages) in by_slot {
        let unique: BTreeSet<_> = packages
            .iter()
            .map(|package| package.rpm_name.clone())
            .collect();
        if unique.len() < 2 {
            continue;
        }

        let (keep, manual_review) = select_dedupe_keep(&packages);
        let remove = packages
            .iter()
            .map(|package| package.rpm_name.clone())
            .filter(|name| name != &keep)
            .collect();
        actions.push(DedupeAction {
            slot,
            keep,
            remove,
            reason: "multiple packages in one compat branch".to_string(),
            manual_review,
        });
    }

    actions
}

fn select_dedupe_keep(packages: &[&IndexedPackage]) -> (String, bool) {
    let stable: Vec<_> = packages
        .iter()
        .copied()
        .filter(|package| !has_prerelease_package_version_marker(package))
        .collect();
    let candidates = if stable.is_empty() {
        packages.to_vec()
    } else {
        stable
    };
    let manual_review = candidates
        .iter()
        .any(|package| parse_version(&package.version).is_empty());
    let keep = candidates
        .into_iter()
        .max_by(|a, b| parse_version(&a.version).cmp(&parse_version(&b.version)))
        .or_else(|| packages.first().copied())
        .map(|package| package.rpm_name.clone())
        .unwrap_or_default();
    (keep, manual_review)
}

fn main_package_capability(package: &IndexedPackage) -> Option<String> {
    package
        .provides
        .iter()
        .find(|provide| provide.subpackage == "main" && !capability_has_feature(&provide.cap))
        .map(|provide| provide.cap.clone())
        .or_else(|| {
            package
                .provides
                .iter()
                .find(|provide| !capability_has_feature(&provide.cap))
                .map(|provide| provide.cap.clone())
        })
}

fn capability_has_feature(capability: &str) -> bool {
    crate_capability_name(capability).is_some_and(|name| name.contains('/'))
}

fn capability_from_rust_package_name(package_name: &str) -> Option<String> {
    package_name
        .strip_prefix("rust-")
        .filter(|name| !name.is_empty())
        .map(|name| format!("crate({name})"))
}

fn print_repo_health(report: &RepoHealthReport) {
    println!("Repo health for {}", report.index);

    println!();
    println!("Rename legacy compat names:");
    if report.rename.is_empty() {
        println!("  (none)");
    } else {
        for action in &report.rename {
            println!("  {} -> {}", action.current, action.target);
        }
    }

    println!();
    println!("Dedupe:");
    if report.dedupe.is_empty() {
        println!("  (none)");
    } else {
        for action in &report.dedupe {
            println!("  {}", action.slot);
            println!("    keep: {}", action.keep);
            if action.remove.is_empty() {
                println!("    remove: (none)");
            } else {
                println!("    remove: {}", action.remove.join(", "));
            }
            if action.manual_review {
                println!("    manual-review");
            }
        }
    }

    println!();
    println!("Pre-release:");
    if report.remove_prerelease.is_empty() {
        println!("  (none)");
    } else {
        for action in &report.remove_prerelease {
            println!("  {} {}", action.package, action.suggested_action);
        }
    }

    println!();
    println!("Exact version packages:");
    if report.exact_version_packages.is_empty() {
        println!("  (none)");
    } else {
        for action in &report.exact_version_packages {
            println!("  {} -> {}", action.package, action.suggested_slot);
        }
    }

    println!();
    println!("Duplicates:");
    if report.duplicates.is_empty() {
        println!("  (none)");
    } else {
        for action in &report.duplicates {
            println!("  {}", action.capability);
            println!("    providers: {}", action.providers);
        }
    }

    let summary = &report.summary;
    println!();
    println!("Summary:");
    println!(
        "  rename={} dedupe={} prerelease={} exact_version_packages={} duplicates={}",
        summary.rename,
        summary.dedupe,
        summary.remove_prerelease,
        summary.exact_version_packages,
        summary.duplicates
    );
}

pub fn run_buildreqs(
    cargo_toml: &Path,
    index_path: Option<&Path>,
    options: BuildReqsOptions,
) -> Result<i32> {
    let index = match index_path {
        Some(path) => {
            let index_content = fs::read_to_string(path)
                .with_context(|| format!("failed to read {}", path.display()))?;
            Some(
                serde_json::from_str(&index_content)
                    .with_context(|| format!("failed to parse {}", path.display()))?,
            )
        }
        None => None,
    };
    let result = build_buildreqs(cargo_toml, index.as_ref(), &options)?;

    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_buildreqs(&result);
    }

    if options.check
        && index_path.is_some()
        && (result.summary.missing > 0 || result.summary.conflicts > 0)
    {
        Ok(1)
    } else {
        Ok(0)
    }
}

pub fn build_buildreqs(
    cargo_toml: &Path,
    index: Option<&RepoIndex>,
    options: &BuildReqsOptions,
) -> Result<BuildReqsResult> {
    let requests = load_buildreq_dependencies(cargo_toml, options)?;
    let check_capabilities = index.is_some();
    let capabilities = index.map(sorted_capabilities).unwrap_or_default();
    let mut buildrequires = Vec::new();
    let mut missing = Vec::new();
    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();

    for request in requests {
        warnings.extend(request.warnings.clone());
        let mut records = buildrequires_for_request(&request);
        buildrequires.append(&mut records);
    }

    dedup_buildrequires(&mut buildrequires);
    if check_capabilities {
        for record in &buildrequires {
            let floor = buildreq_requirement_floor(record.requirement.as_deref());
            let check = analyze_requirement(
                &record.dependency,
                &record.capability,
                &floor,
                &capabilities,
                None,
            );
            match check.status.as_str() {
                "missing" => missing.push(check),
                "conflict" => conflicts.push(check),
                _ => {}
            }
        }
    }
    Ok(BuildReqsResult {
        cargo_toml: display_path(cargo_toml),
        kind: options.kind,
        include_build: options.include_build,
        include_dev: options.include_dev,
        summary: BuildReqsSummary {
            buildrequires: buildrequires.len(),
            missing: missing.len(),
            conflicts: conflicts.len(),
            warnings: warnings.len(),
        },
        buildrequires,
        missing,
        conflicts,
        warnings,
    })
}

fn load_buildreq_dependencies(
    cargo_toml: &Path,
    options: &BuildReqsOptions,
) -> Result<Vec<BuildReqRequest>> {
    let content = fs::read_to_string(cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
    let manifest: Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;

    let mut sections = vec!["dependencies"];
    if options.include_build {
        sections.push("build-dependencies");
    }
    if options.include_dev {
        sections.push("dev-dependencies");
    }

    let mut requests = Vec::new();
    for section in sections {
        let Some(dependencies) = manifest.get(section).and_then(Value::as_table) else {
            continue;
        };
        for (alias, value) in dependencies {
            let Some(request) =
                parse_buildreq_dependency(section, alias.to_string(), value.clone())
            else {
                continue;
            };
            requests.push(request);
        }
    }

    Ok(requests)
}

fn parse_buildreq_dependency(
    section: &str,
    alias: String,
    value: Value,
) -> Option<BuildReqRequest> {
    let (package_name, version, default_features, features) = match value {
        Value::String(version) => (alias.clone(), version, true, Vec::new()),
        Value::Table(table) => {
            let package_name = table
                .get("package")
                .and_then(Value::as_str)
                .unwrap_or(&alias)
                .to_string();
            let version = table
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let default_features = table
                .get("default-features")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let features = table
                .get("features")
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .map(normalize_feature_name)
                        .collect()
                })
                .unwrap_or_default();
            (package_name, version, default_features, features)
        }
        _ => return None,
    };

    let mut warnings = Vec::new();
    if let Some(mut warning) = unsupported_requirement_warning(&package_name, &version) {
        warning.subpackage = section.to_string();
        warning.message =
            "buildreqs only derives lower bounds from simple Cargo requirements in this experimental version"
                .to_string();
        warnings.push(warning);
    }

    let required_version = parse_requirement_floor(&version);
    Some(BuildReqRequest {
        section: section.to_string(),
        repo_pkgname: repo_pkgname_for_dependency(&package_name, &required_version),
        alias,
        package_name,
        version_requirement: version,
        required_version,
        default_features,
        features,
        warnings,
    })
}

fn buildrequires_for_request(request: &BuildReqRequest) -> Vec<BuildRequiresRecord> {
    let mut records = vec![BuildRequiresRecord {
        section: request.section.clone(),
        dependency: request.alias.clone(),
        package: request.package_name.clone(),
        capability: package_capability(&request.repo_pkgname, None),
        requirement: buildreq_requirement_text(request),
        feature: None,
    }];

    let mut features = BTreeSet::new();
    if request.default_features {
        features.insert("default".to_string());
    }
    features.extend(request.features.clone());

    for feature in features {
        records.push(BuildRequiresRecord {
            section: request.section.clone(),
            dependency: request.alias.clone(),
            package: request.package_name.clone(),
            capability: package_capability(&request.repo_pkgname, Some(&feature)),
            requirement: None,
            feature: Some(feature),
        });
    }

    records
}

fn buildreq_requirement_text(request: &BuildReqRequest) -> Option<String> {
    if request.version_requirement.trim().is_empty() {
        None
    } else {
        requirement_text_for_floor(&request.required_version)
    }
}

fn dedup_buildrequires(records: &mut Vec<BuildRequiresRecord>) {
    records.sort_by(|a, b| {
        (
            &a.capability,
            &a.requirement,
            &a.section,
            &a.dependency,
            &a.feature,
        )
            .cmp(&(
                &b.capability,
                &b.requirement,
                &b.section,
                &b.dependency,
                &b.feature,
            ))
    });
    records.dedup_by(|a, b| a.capability == b.capability && a.requirement == b.requirement);
}

fn buildreq_requirement_floor(requirement: Option<&str>) -> Vec<u64> {
    let Some(requirement) = requirement else {
        return Vec::new();
    };
    let version = requirement
        .trim()
        .strip_prefix(">=")
        .unwrap_or(requirement)
        .trim();
    parse_version(version)
}

fn print_buildreqs(result: &BuildReqsResult) {
    for record in &result.buildrequires {
        match &record.requirement {
            Some(requirement) => println!("BuildRequires: {} {}", record.capability, requirement),
            None => println!("BuildRequires: {}", record.capability),
        }
    }
}

pub fn build_repo_plan(
    cargo_toml: &Path,
    index: &RepoIndex,
    check_transitive: bool,
) -> Result<RepoPlanResult> {
    build_repo_plan_with_options(
        cargo_toml,
        index,
        &RepoPlanOptions {
            check_transitive,
            json: false,
            include_global_warnings: false,
        },
    )
}

pub fn build_repo_plan_with_options(
    cargo_toml: &Path,
    index: &RepoIndex,
    options: &RepoPlanOptions,
) -> Result<RepoPlanResult> {
    let check = check_cargo_toml(cargo_toml, index, options.check_transitive)?;
    let warnings = if options.include_global_warnings {
        check.warnings.clone()
    } else {
        repo_plan_related_warnings(&check)
    };
    let mut need_add = Vec::new();
    let mut need_update = Vec::new();
    let mut duplicates = Vec::new();
    let mut unsupported = Vec::new();
    let mut seen_add = BTreeSet::new();
    let mut seen_update = BTreeSet::new();
    let mut seen_duplicates = BTreeSet::new();
    let mut seen_unsupported = BTreeSet::new();

    for record in &check.missing {
        add_need_add_action(record, "missing", &mut seen_add, &mut need_add);
    }
    for record in &check.transitive_missing {
        add_need_add_action(record, "transitive_missing", &mut seen_add, &mut need_add);
    }
    for record in &check.conflicts {
        add_need_update_action(record, "conflicts", &mut seen_update, &mut need_update);
    }
    for record in &check.transitive_conflicts {
        add_need_update_action(
            record,
            "transitive_conflicts",
            &mut seen_update,
            &mut need_update,
        );
    }
    for warning in &warnings {
        match warning.warning_type.as_str() {
            "duplicate-provider" => {
                if seen_duplicates.insert(warning.cap.clone()) {
                    duplicates.push(DuplicateAction {
                        capability: warning.cap.clone(),
                        providers: warning.rpm_name.clone(),
                        reason: "multiple providers for same capability".to_string(),
                    });
                }
            }
            "unsupported-requirement" | "unsupported-requires" => {
                let requirement = warning.requirement.clone();
                let capability = unsupported_warning_capability(warning);
                let key = (
                    warning.warning_type.clone(),
                    capability.clone(),
                    requirement.clone(),
                );
                if seen_unsupported.insert(key) {
                    unsupported.push(UnsupportedAction {
                        action_type: warning.warning_type.clone(),
                        capability,
                        requirement,
                        reason: unsupported_warning_reason(&warning.warning_type).to_string(),
                    });
                }
            }
            _ => {}
        }
    }
    let policy_warnings = warnings
        .iter()
        .filter(|warning| is_repo_plan_policy_warning(&warning.warning_type))
        .cloned()
        .collect();

    Ok(RepoPlanResult {
        cargo_toml: check.cargo_toml,
        summary: RepoPlanSummary {
            need_add: need_add.len(),
            need_update: need_update.len(),
            duplicates: duplicates.len(),
            unsupported: unsupported.len(),
        },
        repo_check_summary: check.summary,
        need_add,
        need_update,
        duplicates,
        unsupported,
        policy_warnings,
        warnings,
    })
}

fn repo_plan_related_warnings(check: &RepoCheckResult) -> Vec<RepoWarning> {
    let mut capabilities = BTreeSet::new();
    let mut providers = BTreeSet::new();
    for record in check
        .ok
        .iter()
        .chain(check.missing.iter())
        .chain(check.conflicts.iter())
        .chain(check.transitive_ok.iter())
        .chain(check.transitive_missing.iter())
        .chain(check.transitive_conflicts.iter())
    {
        capabilities.insert(record.capability.clone());
        if let Some(provider) = &record.provider {
            providers.insert(provider.rpm_name.clone());
        }
    }

    check
        .warnings
        .iter()
        .filter(|warning| {
            repo_plan_warning_is_direct(warning)
                || repo_plan_warning_matches_warning_capability(warning, &capabilities)
                || repo_plan_warning_matches_provider(warning, &providers)
                || warning
                    .requirement
                    .as_deref()
                    .and_then(first_crate_capability)
                    .is_some_and(|capability| capabilities.contains(&capability))
        })
        .cloned()
        .collect()
}

fn repo_plan_warning_is_direct(warning: &RepoWarning) -> bool {
    warning.warning_type == "unsupported-requirement"
        || warning.subpackage == "direct"
        || warning.rpm_name.is_empty()
}

fn repo_plan_warning_matches_warning_capability(
    warning: &RepoWarning,
    capabilities: &BTreeSet<String>,
) -> bool {
    !warning.cap.is_empty() && capabilities.contains(&warning.cap)
}

fn repo_plan_warning_matches_provider(warning: &RepoWarning, providers: &BTreeSet<String>) -> bool {
    if warning.rpm_name.is_empty() {
        return false;
    }
    warning
        .rpm_name
        .split(',')
        .map(str::trim)
        .any(|rpm_name| providers.contains(rpm_name))
}

pub fn run_app_audit(
    ruyispec_dir: &Path,
    package_root: &Path,
    index_path: &Path,
    output: &Path,
) -> Result<()> {
    let index_content = fs::read_to_string(index_path)
        .with_context(|| format!("failed to read {}", index_path.display()))?;
    let index: RepoIndex = serde_json::from_str(&index_content)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;
    let report = build_app_audit_report(ruyispec_dir, package_root, index_path, &index)?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&report)?;
    fs::write(output, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", output.display()))?;
    println!("App audit report: {}", output.display());
    Ok(())
}

pub fn build_app_audit_report(
    ruyispec_dir: &Path,
    package_root: &Path,
    index_path: &Path,
    index: &RepoIndex,
) -> Result<AppAuditReport> {
    let (app_dirs, mut skipped) = rust_application_scan(package_root)?;
    let mut apps = Vec::new();
    for app_dir in app_dirs {
        apps.push(audit_app_dir(&app_dir, index));
    }
    apps.sort_by(|a, b| a.name.cmp(&b.name));
    skipped.sort_by(|a, b| a.name.cmp(&b.name));

    let mut summary = AppAuditSummary {
        total: apps.len(),
        ..Default::default()
    };
    for app in &apps {
        match app.status.as_str() {
            "green" => summary.green += 1,
            "yellow" => summary.yellow += 1,
            "orange" => summary.orange += 1,
            _ => summary.red += 1,
        }
    }

    Ok(AppAuditReport {
        ruyispec_dir: display_path(ruyispec_dir),
        package_root: display_path(package_root),
        index: display_path(index_path),
        apps,
        skipped,
        summary,
    })
}

fn audit_app_dir(app_dir: &Path, index: &RepoIndex) -> AppAuditRecord {
    let name = app_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let cargo_toml = app_dir.join("Cargo.toml");

    match build_repo_plan(&cargo_toml, index, true) {
        Ok(plan) => {
            let status = status_for_plan_summary(&plan.summary).to_string();
            AppAuditRecord {
                name,
                path: display_path(app_dir),
                cargo_toml: display_path(&cargo_toml),
                status,
                summary: plan.summary,
                notes: Vec::new(),
            }
        }
        Err(error) => AppAuditRecord {
            name,
            path: display_path(app_dir),
            cargo_toml: display_path(&cargo_toml),
            status: "red".to_string(),
            summary: RepoPlanSummary {
                need_add: 0,
                need_update: 0,
                duplicates: 0,
                unsupported: 1,
            },
            notes: vec![error.to_string()],
        },
    }
}

fn rust_application_scan(package_root: &Path) -> Result<(Vec<PathBuf>, Vec<AppAuditSkipped>)> {
    let mut app_dirs = Vec::new();
    let mut skipped = Vec::new();
    for entry in fs::read_dir(package_root)
        .with_context(|| format!("failed to read {}", package_root.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        if name.starts_with("rust-") {
            continue;
        }
        let has_spec = has_spec_file(&path)?;
        if !has_spec {
            continue;
        }
        let has_cargo_toml = path.join("Cargo.toml").is_file();
        if has_cargo_toml {
            app_dirs.push(path);
        } else if spec_dir_looks_like_rust_app(&path)? {
            skipped.push(AppAuditSkipped {
                name,
                path: display_path(&path),
                reason: "missing-cargo-toml".to_string(),
                has_spec,
                has_cargo_toml,
            });
        }
    }
    app_dirs.sort();
    skipped.sort_by(|a, b| a.name.cmp(&b.name));
    Ok((app_dirs, skipped))
}

fn spec_dir_looks_like_rust_app(path: &Path) -> Result<bool> {
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry?;
        if !entry.file_type()?.is_file()
            || !entry.path().extension().is_some_and(|ext| ext == "spec")
        {
            continue;
        }
        let content = fs::read_to_string(entry.path())?;
        let lower = content.to_ascii_lowercase();
        if lower.contains("rust application")
            || lower.contains("buildsystem:    rust")
            || lower.contains("buildsystem: rust")
            || lower.contains("%cargo")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn has_spec_file(path: &Path) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.path().extension().is_some_and(|ext| ext == "spec")
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn status_for_plan_summary(summary: &RepoPlanSummary) -> &'static str {
    if summary.unsupported > 0 {
        "red"
    } else if summary.need_update > 0 || summary.duplicates > 0 {
        "orange"
    } else if summary.need_add > 0 {
        "yellow"
    } else {
        "green"
    }
}

fn add_need_add_action(
    record: &CheckRecord,
    source: &str,
    seen: &mut BTreeSet<(String, Option<String>)>,
    actions: &mut Vec<NeedAddAction>,
) {
    let key = (record.capability.clone(), record.requirement.clone());
    if !seen.insert(key) {
        if let Some(action) = actions.iter_mut().find(|action| {
            action.capability == record.capability && action.requirement == record.requirement
        }) {
            if !action.required_by.contains(&record.dependency) {
                action.required_by.push(record.dependency.clone());
                action.required_by.sort();
            }
        }
        return;
    }
    actions.push(NeedAddAction {
        capability: record.capability.clone(),
        suggested_package: suggested_package_for_capability(&record.capability),
        reason: "missing provider".to_string(),
        requirement: record.requirement.clone(),
        required_by: vec![record.dependency.clone()],
        source: source.to_string(),
    });
}

fn add_need_update_action(
    record: &CheckRecord,
    source: &str,
    seen: &mut BTreeSet<(String, String, Option<String>)>,
    actions: &mut Vec<NeedUpdateAction>,
) {
    let Some(provider) = &record.provider else {
        return;
    };
    let key = (
        record.capability.clone(),
        provider.rpm_name.clone(),
        record.requirement.clone(),
    );
    if !seen.insert(key) {
        return;
    }
    actions.push(NeedUpdateAction {
        capability: record.capability.clone(),
        package: provider.rpm_name.clone(),
        current_version: provider.version.clone(),
        required: record.requirement.clone(),
        reason: "provider version does not satisfy requirement".to_string(),
        source: source.to_string(),
    });
}

fn suggested_package_for_capability(capability: &str) -> String {
    match crate_capability_name(capability) {
        Some(name) => {
            let package = name.split('/').next().unwrap_or(name);
            format!("rust-{package}")
        }
        None => capability.to_string(),
    }
}

fn unsupported_warning_capability(warning: &RepoWarning) -> String {
    if !warning.cap.is_empty() {
        return warning.cap.clone();
    }
    warning
        .requirement
        .as_deref()
        .and_then(first_crate_capability)
        .unwrap_or_default()
}

fn unsupported_warning_reason(warning_type: &str) -> &'static str {
    match warning_type {
        "unsupported-requires" => "RPM rich Requires not parsed",
        _ => "complex Cargo requirement not fully supported",
    }
}

fn is_repo_plan_policy_warning(warning_type: &str) -> bool {
    matches!(
        warning_type,
        "prerelease-version" | "exact-version-package" | "legacy-compat-name" | "naming-mismatch"
    )
}

fn crate_capability_name(capability: &str) -> Option<&str> {
    capability
        .strip_prefix("crate(")
        .and_then(|value| value.strip_suffix(')'))
}

fn first_crate_capability(text: &str) -> Option<String> {
    let start = text.find("crate(")?;
    let rest = &text[start..];
    let end = rest.find(')')?;
    Some(rest[..=end].to_string())
}

pub fn check_cargo_toml(
    cargo_toml: &Path,
    index: &RepoIndex,
    check_transitive: bool,
) -> Result<RepoCheckResult> {
    let requests = load_cargo_dependencies(cargo_toml)?;
    let mut direct_ok = Vec::new();
    let mut direct_missing = Vec::new();
    let mut direct_conflicts = Vec::new();
    let mut transitive_ok = Vec::new();
    let mut transitive_missing = Vec::new();
    let mut transitive_conflicts = Vec::new();
    let mut warnings = index.warnings.clone();
    let mut human_blocks = Vec::new();

    for request in requests {
        warnings.extend(request.warnings.clone());
        let (direct, transitive, human) = analyze_dependency(&request, index, check_transitive);
        human_blocks.push(human.join("\n"));

        for record in direct {
            match record.status.as_str() {
                "ok" => direct_ok.push(record),
                "missing" => direct_missing.push(record),
                _ => direct_conflicts.push(record),
            }
        }
        for record in transitive {
            match record.status.as_str() {
                "ok" => transitive_ok.push(record),
                "missing" => transitive_missing.push(record),
                _ => transitive_conflicts.push(record),
            }
        }
    }

    let transitive = transitive_ok
        .iter()
        .chain(transitive_missing.iter())
        .chain(transitive_conflicts.iter())
        .cloned()
        .collect();

    Ok(RepoCheckResult {
        cargo_toml: display_path(cargo_toml),
        summary: RepoCheckSummary {
            ok: direct_ok.len(),
            missing: direct_missing.len(),
            conflicts: direct_conflicts.len(),
            transitive_ok: transitive_ok.len(),
            transitive_missing: transitive_missing.len(),
            transitive_conflicts: transitive_conflicts.len(),
        },
        ok: direct_ok,
        missing: direct_missing,
        conflicts: direct_conflicts,
        transitive,
        transitive_ok,
        transitive_missing,
        transitive_conflicts,
        warnings,
        human_blocks,
    })
}

fn load_cargo_dependencies(cargo_toml: &Path) -> Result<Vec<DepRequest>> {
    let content = fs::read_to_string(cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
    let manifest: Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
    let dependencies = manifest
        .get("dependencies")
        .and_then(Value::as_table)
        .cloned()
        .unwrap_or_default();

    let mut requests = Vec::new();
    for (alias, value) in dependencies {
        let mut warnings = Vec::new();
        let (package_name, version, default_features, features) = match value {
            Value::String(version) => (alias.clone(), version, true, Vec::new()),
            Value::Table(table) => {
                let package_name = table
                    .get("package")
                    .and_then(Value::as_str)
                    .unwrap_or(&alias)
                    .to_string();
                let version = table
                    .get("version")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let default_features = table
                    .get("default-features")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let features = table
                    .get("features")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(normalize_feature_name)
                            .collect()
                    })
                    .unwrap_or_default();
                (package_name, version, default_features, features)
            }
            _ => continue,
        };

        if let Some(warning) = unsupported_requirement_warning(&package_name, &version) {
            warnings.push(warning);
        }
        let required_version = parse_requirement_floor(&version);
        requests.push(DepRequest {
            repo_pkgname: repo_pkgname_for_dependency(&package_name, &required_version),
            alias,
            package_name,
            required_version,
            default_features,
            features,
            warnings,
        });
    }

    Ok(requests)
}

fn unsupported_requirement_warning(cargo_name: &str, requirement: &str) -> Option<RepoWarning> {
    let requirement = requirement.trim();
    if requirement.is_empty() {
        return Some(RepoWarning {
            warning_type: "unsupported-requirement".to_string(),
            rpm_name: String::new(),
            subpackage: "direct".to_string(),
            cap: cargo_name.to_string(),
            normalized_version: None,
            requirement: Some(requirement.to_string()),
            line: None,
            expected: None,
            message: "dependency has no simple version requirement; repo-check treated it as any"
                .to_string(),
        });
    }
    if simple_requirement_floor_token(requirement).is_none() {
        Some(RepoWarning {
            warning_type: "unsupported-requirement".to_string(),
            rpm_name: String::new(),
            subpackage: "direct".to_string(),
            cap: cargo_name.to_string(),
            normalized_version: None,
            requirement: Some(requirement.to_string()),
            line: None,
            expected: None,
            message: "repo-check only derives lower bounds from simple Cargo requirements in this experimental version".to_string(),
        })
    } else {
        None
    }
}

fn analyze_dependency(
    request: &DepRequest,
    index: &RepoIndex,
    check_transitive: bool,
) -> (Vec<CheckRecord>, Vec<CheckRecord>, Vec<String>) {
    let capabilities = sorted_capabilities(index);
    let packages_by_provider = packages_by_provider(index);
    let candidates = crate_name_candidates(index, &request.package_name);
    let mut direct = Vec::new();
    let mut transitive = Vec::new();
    let mut human = vec![format!(
        "  {} (version >= {})",
        request.alias,
        format_version(&request.required_version)
    )];
    let pkgname = &request.repo_pkgname;

    let mut selected_features = Vec::new();
    if request.default_features {
        selected_features.push("default".to_string());
    }
    selected_features.extend(request.features.clone());

    let mut checked_caps = vec![package_capability(pkgname, None)];
    checked_caps.extend(
        selected_features
            .iter()
            .map(|feature| package_capability(pkgname, Some(feature))),
    );

    for cap in checked_caps {
        let floor = if cap == package_capability(pkgname, None) {
            request.required_version.clone()
        } else {
            Vec::new()
        };
        let diagnostic = if cap == package_capability(pkgname, None) {
            rejected_candidate_message(&request.repo_pkgname, &candidates)
        } else {
            None
        };
        let result = analyze_requirement(&request.alias, &cap, &floor, &capabilities, diagnostic);
        if result.status == "missing" {
            human.push(format!("    {} -> no provider found", cap));
            direct.push(result);
            continue;
        }
        if result.status == "conflict" {
            let provider = result.provider.as_ref().unwrap();
            human.push(format!(
                "    {} -> provider {} {} does not satisfy requirement >= {}",
                cap,
                provider.rpm_name,
                provider.version,
                format_version(&floor)
            ));
            direct.push(result);
            continue;
        }

        let provider = result.provider.clone().unwrap();
        human.push(format!(
            "    {} -> {} {}",
            cap, provider.rpm_name, provider.version
        ));
        direct.push(result);

        if check_transitive {
            walk_transitive(
                &request.alias,
                provider,
                &capabilities,
                &packages_by_provider,
                vec![request.alias.clone(), cap],
                &mut BTreeSet::new(),
                &mut transitive,
            );
        }
    }

    (direct, transitive, human)
}

fn sorted_capabilities(index: &RepoIndex) -> BTreeMap<String, Vec<CapabilityProvider>> {
    let mut capabilities = index.capabilities.clone();
    for providers in capabilities.values_mut() {
        providers.sort_by(|a, b| parse_version(&b.version).cmp(&parse_version(&a.version)));
    }
    capabilities
}

fn packages_by_provider(index: &RepoIndex) -> BTreeMap<(String, String), IndexedPackage> {
    let mut map = BTreeMap::new();
    for package in &index.packages {
        map.insert(
            (package.rpm_name.clone(), "main".to_string()),
            package.clone(),
        );
        for provide in &package.provides {
            map.insert(
                (package.rpm_name.clone(), provide.subpackage.clone()),
                package.clone(),
            );
        }
    }
    map
}

fn crate_name_candidates<'a>(index: &'a RepoIndex, cargo_name: &str) -> Vec<&'a IndexedPackage> {
    let normalized = normalize_crate_name(cargo_name);
    index
        .packages
        .iter()
        .filter(|package| normalize_crate_name(&package.crate_name) == normalized)
        .collect()
}

fn rejected_candidate_message(
    expected_pkgname: &str,
    candidates: &[&IndexedPackage],
) -> Option<String> {
    let rejected: Vec<_> = candidates
        .iter()
        .filter(|package| package.pkgname != expected_pkgname)
        .map(|package| format!("{} {}", package.pkgname, package.version))
        .collect();
    if rejected.is_empty() {
        None
    } else {
        Some(format!(
            "no provider found; expected capability crate({expected_pkgname}); rejected candidate(s): {}",
            rejected.join(", ")
        ))
    }
}

fn analyze_requirement(
    root_dependency: &str,
    capability: &str,
    required_floor: &[u64],
    capabilities: &BTreeMap<String, Vec<CapabilityProvider>>,
    missing_diagnostic: Option<String>,
) -> CheckRecord {
    let resolution = select_provider(capabilities, capability, required_floor);
    let chain = vec![root_dependency.to_string(), capability.to_string()];
    match resolution.status {
        "ok" => CheckRecord {
            dependency: root_dependency.to_string(),
            capability: capability.to_string(),
            status: "ok".to_string(),
            requirement: requirement_text_for_floor(required_floor),
            provider: resolution.provider,
            chain,
            message: None,
        },
        "conflict" => CheckRecord {
            dependency: root_dependency.to_string(),
            capability: capability.to_string(),
            status: "conflict".to_string(),
            requirement: requirement_text_for_floor(required_floor),
            provider: resolution.provider,
            chain,
            message: resolution.message,
        },
        _ => CheckRecord {
            dependency: root_dependency.to_string(),
            capability: capability.to_string(),
            status: "missing".to_string(),
            requirement: requirement_text_for_floor(required_floor),
            provider: None,
            chain,
            message: Some(missing_diagnostic.unwrap_or_else(|| "no provider found".to_string())),
        },
    }
}

fn walk_transitive(
    root_dependency: &str,
    provider: CapabilityProvider,
    capabilities: &BTreeMap<String, Vec<CapabilityProvider>>,
    packages_by_provider: &BTreeMap<(String, String), IndexedPackage>,
    chain: Vec<String>,
    seen: &mut BTreeSet<(String, String)>,
    records: &mut Vec<CheckRecord>,
) {
    let key = (provider.rpm_name.clone(), provider.subpackage.clone());
    if !seen.insert(key.clone()) {
        return;
    }
    let Some(package) = packages_by_provider.get(&key) else {
        return;
    };

    for requirement in package
        .requires
        .iter()
        .filter(|requirement| requirement.subpackage == provider.subpackage)
    {
        let requirement_text =
            build_requirement_text(requirement.op.as_deref(), requirement.version.as_deref());
        let mut next_chain = chain.clone();
        next_chain.push(format!(
            "requires {}{}",
            requirement.cap,
            requirement_text
                .as_ref()
                .map(|text| format!(" {text}"))
                .unwrap_or_default()
        ));

        let resolution = select_provider_for_requirement(
            capabilities,
            &requirement.cap,
            requirement.op.as_deref(),
            requirement.version.as_deref(),
        );
        if resolution.provider.is_none() {
            records.push(CheckRecord {
                dependency: root_dependency.to_string(),
                capability: requirement.cap.clone(),
                status: "missing".to_string(),
                requirement: requirement_text,
                provider: None,
                chain: next_chain,
                message: Some("no provider found".to_string()),
            });
            continue;
        }
        if resolution.status == "conflict" {
            records.push(CheckRecord {
                dependency: root_dependency.to_string(),
                capability: requirement.cap.clone(),
                status: "conflict".to_string(),
                requirement: requirement_text,
                provider: resolution.provider,
                chain: next_chain,
                message: resolution.message,
            });
            continue;
        }

        let selected = resolution.provider.unwrap();
        let mut ok_chain = next_chain;
        ok_chain.push(format!(
            "selected/provider {} version {}",
            selected.rpm_name, selected.version
        ));
        records.push(CheckRecord {
            dependency: root_dependency.to_string(),
            capability: requirement.cap.clone(),
            status: "ok".to_string(),
            requirement: requirement_text,
            provider: Some(selected.clone()),
            chain: ok_chain.clone(),
            message: None,
        });
        walk_transitive(
            root_dependency,
            selected,
            capabilities,
            packages_by_provider,
            ok_chain,
            seen,
            records,
        );
    }
}

fn select_provider(
    capabilities: &BTreeMap<String, Vec<CapabilityProvider>>,
    cap: &str,
    minimum_version: &[u64],
) -> Resolution {
    let providers = capabilities.get(cap).cloned().unwrap_or_default();
    if providers.is_empty() {
        return Resolution {
            provider: None,
            status: "missing",
            message: Some("no provider found".to_string()),
        };
    }

    if let Some(provider) = providers
        .iter()
        .find(|provider| version_at_least(&provider.version, minimum_version))
        .cloned()
    {
        return Resolution {
            provider: Some(provider),
            status: "ok",
            message: None,
        };
    }

    let provider = providers.into_iter().next().unwrap();
    if minimum_version.is_empty() {
        Resolution {
            provider: Some(provider),
            status: "ok",
            message: None,
        }
    } else {
        Resolution {
            message: Some(format!(
                "selected/provider {} version {} does not satisfy requirement >= {}",
                provider.rpm_name,
                provider.version,
                format_version(minimum_version)
            )),
            provider: Some(provider),
            status: "conflict",
        }
    }
}

fn select_provider_for_requirement(
    capabilities: &BTreeMap<String, Vec<CapabilityProvider>>,
    cap: &str,
    op: Option<&str>,
    version: Option<&str>,
) -> Resolution {
    match (op, version) {
        (Some(">="), Some(version)) => select_provider(capabilities, cap, &parse_version(version)),
        (Some("="), Some(version)) => select_exact_provider(capabilities, cap, version),
        _ => select_provider(capabilities, cap, &[]),
    }
}

fn select_exact_provider(
    capabilities: &BTreeMap<String, Vec<CapabilityProvider>>,
    cap: &str,
    exact_version: &str,
) -> Resolution {
    let providers = capabilities.get(cap).cloned().unwrap_or_default();
    if providers.is_empty() {
        return Resolution {
            provider: None,
            status: "missing",
            message: Some("no provider found".to_string()),
        };
    }

    if let Some(provider) = providers
        .iter()
        .find(|provider| version_equals(&provider.version, exact_version))
        .cloned()
    {
        return Resolution {
            provider: Some(provider),
            status: "ok",
            message: None,
        };
    }

    let provider = providers.into_iter().next().unwrap();
    Resolution {
        message: Some(format!(
            "selected/provider {} version {} does not satisfy requirement = {}",
            provider.rpm_name, provider.version, exact_version
        )),
        provider: Some(provider),
        status: "conflict",
    }
}

fn parse_version(version: &str) -> Vec<u64> {
    let mut parts = Vec::new();
    for token in version.split('.') {
        let digits: String = token.chars().take_while(|ch| ch.is_ascii_digit()).collect();
        if digits.is_empty() {
            break;
        }
        if let Ok(part) = digits.parse() {
            parts.push(part);
        }
    }
    parts
}

fn parse_requirement_floor(requirement: &str) -> Vec<u64> {
    simple_requirement_floor_token(requirement)
        .map(parse_version)
        .unwrap_or_default()
}

fn simple_requirement_floor_token(requirement: &str) -> Option<&str> {
    let requirement = requirement.trim();
    if requirement.is_empty()
        || requirement.contains(',')
        || requirement.contains('*')
        || requirement.starts_with('<')
        || requirement.starts_with('=')
        || requirement.starts_with('~')
        || (requirement.starts_with('>') && !requirement.starts_with(">="))
    {
        return None;
    }

    if let Some(version) = requirement.strip_prefix('^') {
        return Some(version.trim());
    }
    if let Some(version) = requirement.strip_prefix(">=") {
        return Some(version.trim());
    }
    Some(requirement)
}

fn compat_branch(version: &[u64]) -> Option<String> {
    if version.is_empty() {
        return None;
    }
    let major = version[0];
    let minor = version.get(1).copied().unwrap_or(0);
    let patch = version.get(2).copied().unwrap_or(0);
    if major > 0 {
        Some(major.to_string())
    } else if minor > 0 {
        Some(format!("0.{minor}"))
    } else {
        Some(format!("0.0.{patch}"))
    }
}

fn repo_pkgname_for_dependency(cargo_name: &str, version: &[u64]) -> String {
    let base = cargo_name.replace('_', "-");
    match compat_branch(version) {
        Some(branch) => format!("{base}-{branch}"),
        None => base,
    }
}

fn version_at_least(version: &str, minimum: &[u64]) -> bool {
    if minimum.is_empty() {
        return true;
    }
    let mut current = parse_version(version);
    let mut minimum = minimum.to_vec();
    let len = current.len().max(minimum.len());
    current.resize(len, 0);
    minimum.resize(len, 0);
    current >= minimum
}

fn version_equals(version: &str, exact: &str) -> bool {
    let mut current = parse_version(version);
    let mut exact = parse_version(exact);
    let len = current.len().max(exact.len());
    current.resize(len, 0);
    exact.resize(len, 0);
    current == exact
}

fn format_version(version: &[u64]) -> String {
    if version.is_empty() {
        "any".to_string()
    } else {
        version
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }
}

fn requirement_text_for_floor(version: &[u64]) -> Option<String> {
    if version.is_empty() {
        None
    } else {
        Some(format!(">={}", format_version(version)))
    }
}

fn build_requirement_text(op: Option<&str>, version: Option<&str>) -> Option<String> {
    match (op, version) {
        (Some(op), Some(version)) => Some(format!("{op} {version}")),
        _ => None,
    }
}

fn package_capability(pkgname: &str, feature: Option<&String>) -> String {
    match feature {
        Some(feature) => format!("crate({pkgname}/{feature})"),
        None => format!("crate({pkgname})"),
    }
}

fn normalize_feature_name(feature: &str) -> String {
    feature.replace('_', "-").to_ascii_lowercase()
}

fn normalize_crate_name(value: &str) -> String {
    value.replace('-', "_")
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

fn print_human_result(result: &RepoCheckResult) {
    println!("Checking {}", result.cargo_toml);
    for block in &result.human_blocks {
        println!("{block}");
    }
    let summary = &result.summary;
    println!(
        "summary: ok={}, missing={}, conflicts={}, transitive_ok={}, transitive_missing={}, transitive_conflicts={}",
        summary.ok,
        summary.missing,
        summary.conflicts,
        summary.transitive_ok,
        summary.transitive_missing,
        summary.transitive_conflicts
    );
}

fn print_human_plan(result: &RepoPlanResult) {
    println!("Repo plan for {}", result.cargo_toml);

    println!();
    println!("Need add:");
    if result.need_add.is_empty() {
        println!("  (none)");
    } else {
        for action in &result.need_add {
            println!("  {}", action.suggested_package);
            println!("    capability: {}", action.capability);
            if let Some(requirement) = &action.requirement {
                println!("    requirement: {requirement}");
            }
            println!("    reason: {}", action.reason);
        }
    }

    println!();
    println!("Need update:");
    if result.need_update.is_empty() {
        println!("  (none)");
    } else {
        for action in &result.need_update {
            println!("  {}", action.package);
            println!("    current: {}", action.current_version);
            if let Some(required) = &action.required {
                println!("    required: {required}");
            }
            println!("    capability: {}", action.capability);
        }
    }

    println!();
    println!("Duplicates:");
    if result.duplicates.is_empty() {
        println!("  (none)");
    } else {
        for action in &result.duplicates {
            println!("  {}", action.capability);
            println!("    providers: {}", action.providers);
        }
    }

    println!();
    println!("Unsupported:");
    if result.unsupported.is_empty() {
        println!("  (none)");
    } else {
        for action in &result.unsupported {
            let requirement = action.requirement.as_deref().unwrap_or("");
            println!(
                "  {} {} {}",
                action.action_type, action.capability, requirement
            );
        }
    }

    println!();
    println!("Policy warnings:");
    if result.policy_warnings.is_empty() {
        println!("  (none)");
    } else {
        for warning in &result.policy_warnings {
            println!("  {} {}", warning.warning_type, warning.rpm_name);
            if let Some(expected) = &warning.expected {
                println!("    expected: {expected}");
            }
            println!("    {}", warning.message);
        }
    }

    let summary = &result.summary;
    println!();
    println!("Summary:");
    println!(
        "  need_add={} need_update={} duplicates={} unsupported={}",
        summary.need_add, summary.need_update, summary.duplicates, summary.unsupported
    );
}

pub fn validate_json_summary(path: &Path) -> Result<RepoCheckSummary> {
    let content = fs::read_to_string(path)?;
    let result: RepoCheckResult = serde_json::from_str(&content)?;
    Ok(result.summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(rpm_name: &str, version: &str) -> CapabilityProvider {
        CapabilityProvider {
            rpm_name: rpm_name.to_string(),
            subpackage: "main".to_string(),
            version: version.to_string(),
        }
    }

    fn policy_package(rpm_name: &str, crate_name: &str, version: &str) -> IndexedPackage {
        IndexedPackage {
            rpm_name: rpm_name.to_string(),
            version: version.to_string(),
            crate_name: crate_name.to_string(),
            pkgname: repo_pkgname_for_dependency(crate_name, &parse_version(version)),
            spec_path: String::new(),
            provides: Vec::new(),
            requires: Vec::new(),
        }
    }

    #[test]
    fn parse_version_keeps_numeric_prefixes() {
        assert_eq!(parse_version("1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_version("0.22.1"), vec![0, 22, 1]);
        assert_eq!(parse_version("1.2.3-alpha"), vec![1, 2, 3]);
    }

    #[test]
    fn parse_requirement_floor_accepts_simple_cargo_lower_bounds() {
        assert_eq!(parse_requirement_floor("1.2.3"), vec![1, 2, 3]);
        assert_eq!(parse_requirement_floor("^0.3.16"), vec![0, 3, 16]);
        assert_eq!(parse_requirement_floor(">=1.2.3"), vec![1, 2, 3]);
        assert!(parse_requirement_floor(">=1.2, <1.6").is_empty());
        assert!(parse_requirement_floor("=1.5.0").is_empty());
    }

    #[test]
    fn compat_branch_matches_cargo_compat_policy() {
        assert_eq!(compat_branch(&[1, 2, 3]), Some("1".to_string()));
        assert_eq!(compat_branch(&[0, 22, 1]), Some("0.22".to_string()));
        assert_eq!(compat_branch(&[0, 0, 7]), Some("0.0.7".to_string()));
    }

    #[test]
    fn repo_pkgname_uses_normalized_crate_name_and_compat_branch() {
        assert_eq!(
            repo_pkgname_for_dependency("base64", &[0, 22, 1]),
            "base64-0.22"
        );
        assert_eq!(
            repo_pkgname_for_dependency("serde_with", &[3, 18, 0]),
            "serde-with-3"
        );
    }

    #[test]
    fn prerelease_detection_only_checks_version_segments() {
        assert!(has_prerelease_version_marker("0.6.0-rc.10"));
        assert!(has_prerelease_version_marker("1.2.3-alpha.1"));
        assert!(has_prerelease_version_marker("1.2.3-beta"));
        assert!(has_prerelease_version_marker("1.2.3-pre.4"));
        assert!(!has_prerelease_version_marker("15.1.0"));
        assert!(!has_prerelease_version_marker("im-rc-15.0"));
    }

    #[test]
    fn package_policy_warning_types_are_specific() {
        assert_eq!(
            package_policy_warning_type(&policy_package("rust-clap-4.0", "clap", "4.5.50")),
            "legacy-compat-name"
        );
        assert_eq!(
            package_policy_warning_type(&policy_package("rust-regex-1.0", "regex", "1.12.2")),
            "legacy-compat-name"
        );
        assert_eq!(
            package_policy_warning_type(&policy_package("rust-serde-1.0", "serde", "1.0.228")),
            "legacy-compat-name"
        );
        assert_ne!(
            package_policy_warning_type(&policy_package("rust-base64-0.22", "base64", "0.22.1")),
            "legacy-compat-name"
        );
        assert_eq!(
            package_policy_warning_type(&policy_package("rust-cc-1.2.61", "cc", "1.2.61")),
            "exact-version-package"
        );
        assert_eq!(
            package_policy_warning_type(&policy_package("rust-aead-0.6.0-rc.10", "aead", "0.6.0")),
            "prerelease-version"
        );
        assert_ne!(
            package_policy_warning_type(&policy_package("rust-im-rc-15.0", "im_rc", "15.1.0")),
            "prerelease-version"
        );
    }

    #[test]
    fn suggested_package_is_derived_from_capability_package_part() {
        assert_eq!(
            suggested_package_for_capability("crate(base64-0.22)"),
            "rust-base64-0.22"
        );
        assert_eq!(
            suggested_package_for_capability("crate(serde-with-3/base64)"),
            "rust-serde-with-3"
        );
        assert_eq!(
            suggested_package_for_capability("crate(foo-1/default)"),
            "rust-foo-1"
        );
    }

    #[test]
    fn unsupported_requirement_warning_flags_complex_requirements() {
        for requirement in [">=1.2, <1.6", "=1.5.0", "~1.5"] {
            let warning = unsupported_requirement_warning("foo", requirement)
                .expect("complex requirement should warn");
            assert_eq!(warning.warning_type, "unsupported-requirement");
            assert_eq!(warning.requirement.as_deref(), Some(requirement));
        }
    }

    #[test]
    fn unsupported_requirement_warning_allows_simple_requirements() {
        assert!(unsupported_requirement_warning("foo", "1").is_none());
        assert!(unsupported_requirement_warning("foo", "0.22").is_none());
        assert!(unsupported_requirement_warning("foo", "^0.3.16").is_none());
        assert!(unsupported_requirement_warning("foo", ">=1.2.3").is_none());
    }

    #[test]
    fn buildreqs_normalizes_caret_dependency_to_compat_capability() {
        let request = parse_buildreq_dependency(
            "build-dependencies",
            "pkg-config".to_string(),
            toml::Value::String("^0.3.16".to_string()),
        )
        .expect("dependency should parse");
        assert_eq!(request.repo_pkgname, "pkg-config-0.3");
        assert!(request.warnings.is_empty());

        let records = buildrequires_for_request(&request);
        assert!(records.iter().any(|record| {
            record.capability == "crate(pkg-config-0.3)"
                && record.requirement.as_deref() == Some(">=0.3.16")
        }));
    }

    #[test]
    fn select_provider_accepts_matching_version_floor() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            "crate(base64-0.22)".to_string(),
            vec![provider("rust-base64-0.22", "0.22.1")],
        );

        let resolution = select_provider(&capabilities, "crate(base64-0.22)", &[0, 22, 1]);
        assert_eq!(resolution.status, "ok");
        assert_eq!(
            resolution
                .provider
                .as_ref()
                .map(|provider| provider.version.as_str()),
            Some("0.22.1")
        );
    }

    #[test]
    fn select_provider_conflicts_when_version_is_too_low() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            "crate(base64-0.22)".to_string(),
            vec![provider("rust-base64-0.22", "0.22.0")],
        );

        let resolution = select_provider(&capabilities, "crate(base64-0.22)", &[0, 22, 1]);
        assert_eq!(resolution.status, "conflict");
        assert_eq!(
            resolution
                .provider
                .as_ref()
                .map(|provider| provider.version.as_str()),
            Some("0.22.0")
        );
    }

    #[test]
    fn select_provider_skips_low_version_when_later_provider_satisfies() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            "crate(base64-0.22)".to_string(),
            vec![
                provider("rust-base64-0.22-old", "0.22.0"),
                provider("rust-base64-0.22", "0.22.1"),
            ],
        );

        let resolution = select_provider(&capabilities, "crate(base64-0.22)", &[0, 22, 1]);
        assert_eq!(resolution.status, "ok");
        let selected = resolution.provider.expect("provider should be selected");
        assert_eq!(selected.rpm_name, "rust-base64-0.22");
        assert_eq!(selected.version, "0.22.1");
    }

    #[test]
    fn select_provider_for_equal_requirement_checks_exact_version() {
        let mut capabilities = BTreeMap::new();
        capabilities.insert(
            "crate(clap-4)".to_string(),
            vec![provider("rust-clap-4", "4.6.0")],
        );

        let resolution = select_provider_for_requirement(
            &capabilities,
            "crate(clap-4)",
            Some("="),
            Some("4.6.1"),
        );
        assert_eq!(resolution.status, "conflict");
        assert!(resolution
            .message
            .as_deref()
            .unwrap_or_default()
            .contains("requirement = 4.6.1"));

        capabilities.insert(
            "crate(clap-4)".to_string(),
            vec![provider("rust-clap-4", "4.6.1")],
        );
        let resolution = select_provider_for_requirement(
            &capabilities,
            "crate(clap-4)",
            Some("="),
            Some("4.6.1"),
        );
        assert_eq!(resolution.status, "ok");
    }

    #[test]
    fn need_add_action_merges_required_by_sources() {
        let mut seen = BTreeSet::new();
        let mut actions = Vec::new();
        for dependency in ["serde", "clap", "serde"] {
            add_need_add_action(
                &CheckRecord {
                    dependency: dependency.to_string(),
                    capability: "crate(unicode-ident-1/default)".to_string(),
                    status: "missing".to_string(),
                    requirement: Some(">= 1.0.0".to_string()),
                    provider: None,
                    chain: Vec::new(),
                    message: None,
                },
                "transitive_missing",
                &mut seen,
                &mut actions,
            );
        }

        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].suggested_package, "rust-unicode-ident-1");
        assert_eq!(actions[0].required_by, vec!["clap", "serde"]);
    }
}
