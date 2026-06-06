use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use toml::Value;
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoIndex {
    pub packages: Vec<IndexedPackage>,
    pub capabilities: BTreeMap<String, Vec<CapabilityProvider>>,
    pub warnings: Vec<RepoWarning>,
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
    if !spec_root.is_dir() {
        bail!(
            "spec repo directory does not exist: {}",
            spec_root.display()
        );
    }

    let mut packages = Vec::new();
    let mut capabilities: BTreeMap<String, Vec<CapabilityProvider>> = BTreeMap::new();
    let mut warnings = Vec::new();

    let mut spec_paths = Vec::new();
    for entry in WalkDir::new(spec_root) {
        let entry = entry?;
        if entry.file_type().is_file() && entry.path().extension().is_some_and(|ext| ext == "spec")
        {
            spec_paths.push(entry.path().to_path_buf());
        }
    }
    spec_paths.sort();

    for spec_path in spec_paths {
        let (package, package_warnings) = parse_spec(&spec_path)?;
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
                message: "multiple packages/subpackages provide the same crate capability"
                    .to_string(),
            });
        }
    }

    Ok(RepoIndex {
        packages,
        capabilities,
        warnings,
    })
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
    let index = build_repo_index(spec_root)?;
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let json = serde_json::to_string_pretty(&index)?;
    fs::write(output, format!("{json}\n"))
        .with_context(|| format!("failed to write {}", output.display()))?;
    println!("Repo index: {}", output.display());
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
    options: RepoCheckOptions,
) -> Result<i32> {
    let index_content = fs::read_to_string(index_path)
        .with_context(|| format!("failed to read {}", index_path.display()))?;
    let index: RepoIndex = serde_json::from_str(&index_content)
        .with_context(|| format!("failed to parse {}", index_path.display()))?;
    let result = build_repo_plan(cargo_toml, &index, options.check_transitive)?;

    if options.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print_human_plan(&result);
    }

    Ok(0)
}

pub fn build_repo_plan(
    cargo_toml: &Path,
    index: &RepoIndex,
    check_transitive: bool,
) -> Result<RepoPlanResult> {
    let check = check_cargo_toml(cargo_toml, index, check_transitive)?;
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
    for warning in &check.warnings {
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
        warnings: check.warnings,
    })
}

fn add_need_add_action(
    record: &CheckRecord,
    source: &str,
    seen: &mut BTreeSet<(String, Option<String>)>,
    actions: &mut Vec<NeedAddAction>,
) {
    let key = (record.capability.clone(), record.requirement.clone());
    if !seen.insert(key) {
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
        let required_version = parse_version(&version);
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
    if requirement.is_empty() {
        return Some(RepoWarning {
            warning_type: "unsupported-requirement".to_string(),
            rpm_name: String::new(),
            subpackage: "direct".to_string(),
            cap: cargo_name.to_string(),
            normalized_version: None,
            requirement: Some(requirement.to_string()),
            line: None,
            message: "dependency has no simple version requirement; repo-check treated it as any"
                .to_string(),
        });
    }
    if requirement.contains(',')
        || requirement.contains('*')
        || requirement.starts_with('<')
        || requirement.starts_with('>')
        || requirement.starts_with('=')
        || requirement.starts_with('~')
        || requirement.starts_with('^')
    {
        Some(RepoWarning {
            warning_type: "unsupported-requirement".to_string(),
            rpm_name: String::new(),
            subpackage: "direct".to_string(),
            cap: cargo_name.to_string(),
            normalized_version: None,
            requirement: Some(requirement.to_string()),
            line: None,
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
        let req_floor = if requirement.op.as_deref() == Some(">=") {
            requirement
                .version
                .as_deref()
                .map(parse_version)
                .unwrap_or_default()
        } else {
            Vec::new()
        };
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

        let resolution = select_provider(capabilities, &requirement.cap, &req_floor);
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
