use anyhow::{Context, Result};
use regex::Regex;
use semver::Version;
use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::takopack::spec::normalize_feature_name;
use crate::util::calculate_compat_version;

#[derive(Debug, Clone, Default)]
pub struct BuildRequiresClosureValidation {
    pub root_requirements: usize,
    pub flattened_requirements: usize,
    pub covered_flattened_requirements: usize,
    pub missing_flattened_requirements: usize,
    pub missing_by_package: BTreeMap<String, Vec<String>>,
    pub missing_by_reason: BTreeMap<String, Vec<String>>,
    pub closure_capabilities: usize,
    pub provider_specs_scanned: usize,
    pub provider_cargo_toml_files_scanned: usize,
    pub provider_cargo_feature_edges_added: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Requirement {
    cap: String,
    lower_bound: Option<Version>,
    raw: String,
}

#[derive(Debug, Clone)]
struct BuildReqRecord {
    requirement: Requirement,
    raw_line: String,
}

#[derive(Debug, Clone)]
struct Edge {
    to: Requirement,
}

#[derive(Debug, Default)]
struct CapabilityGraph {
    edges: BTreeMap<String, Vec<Edge>>,
    provider_specs_scanned: usize,
    provider_cargo_toml_files_scanned: usize,
    provider_cargo_feature_edges_added: usize,
}

#[derive(Debug, Default)]
struct Closure {
    lower_bounds: BTreeMap<String, Option<Version>>,
}

#[derive(Debug)]
struct BuildReqRegexes {
    build_requires: Regex,
    provides: Regex,
    requires: Regex,
    crate_cap: Regex,
    macro_ref: Regex,
}

fn regexes() -> &'static BuildReqRegexes {
    static REGEXES: OnceLock<BuildReqRegexes> = OnceLock::new();
    REGEXES.get_or_init(|| BuildReqRegexes {
        build_requires: Regex::new(r"^BuildRequires:\s*(.*)$").unwrap(),
        provides: Regex::new(r"^Provides:\s*(.*)$").unwrap(),
        requires: Regex::new(r"^Requires:\s*(.*)$").unwrap(),
        crate_cap: Regex::new(r"crate\(([^)]+)\)(?:\s*(>=|=)\s*([^\s,]+))?").unwrap(),
        macro_ref: Regex::new(r"%\{([^}]+)\}").unwrap(),
    })
}

pub fn validate_buildrequires_closure(
    root_buildrequires: &[String],
    flattened_buildrequires: &[String],
    ruyispec_root: &Path,
) -> Result<BuildRequiresClosureValidation> {
    let graph = build_provider_graph(ruyispec_root)?;
    let roots = parse_buildrequires_lines(root_buildrequires);
    let flattened = parse_buildrequires_lines(flattened_buildrequires);
    let closure = compute_closure(&roots, &graph);

    let mut covered = 0usize;
    let mut missing_by_package: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut missing_by_reason: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for record in &flattened {
        if covers_requirement(
            closure.lower_bounds.get(&record.requirement.cap),
            &record.requirement,
        ) {
            covered += 1;
        } else {
            missing_by_package
                .entry(capability_package_key(&record.requirement.cap))
                .or_default()
                .push(record.raw_line.trim().to_string());
            missing_by_reason
                .entry(missing_reason(&record.requirement, &closure))
                .or_default()
                .push(record.raw_line.trim().to_string());
        }
    }

    Ok(BuildRequiresClosureValidation {
        root_requirements: roots.len(),
        flattened_requirements: flattened.len(),
        covered_flattened_requirements: covered,
        missing_flattened_requirements: flattened.len().saturating_sub(covered),
        missing_by_package,
        missing_by_reason,
        closure_capabilities: closure.lower_bounds.len(),
        provider_specs_scanned: graph.provider_specs_scanned,
        provider_cargo_toml_files_scanned: graph.provider_cargo_toml_files_scanned,
        provider_cargo_feature_edges_added: graph.provider_cargo_feature_edges_added,
    })
}

fn build_provider_graph(ruyispec_root: &Path) -> Result<CapabilityGraph> {
    let specs_root = ruyispec_specs_root(ruyispec_root);
    if !specs_root.is_dir() {
        anyhow::bail!(
            "ruyispec SPECS directory does not exist: {}",
            specs_root.display()
        );
    }

    let mut graph = CapabilityGraph::default();
    for dir in sorted_read_dir(&specs_root)? {
        if !dir.is_dir() {
            continue;
        }
        let Some(name) = dir.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.starts_with("rust-") {
            continue;
        }

        for spec_file in sorted_read_dir(&dir)?
            .into_iter()
            .filter(|path| path.extension().is_some_and(|ext| ext == "spec"))
        {
            graph.provider_specs_scanned += 1;
            add_spec_edges(&spec_file, &mut graph.edges)?;
        }

        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.is_file() {
            graph.provider_cargo_toml_files_scanned += 1;
            graph.provider_cargo_feature_edges_added +=
                add_simple_cargo_feature_graph_edges(&cargo_toml, &mut graph.edges)?;
        }
    }

    Ok(graph)
}

fn add_spec_edges(path: &Path, edges: &mut BTreeMap<String, Vec<Edge>>) -> Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    let mut macros = BTreeMap::new();
    let mut provides = Vec::new();
    let mut requires = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("%global ") {
            define_macro(rest, &mut macros);
            continue;
        }
        if line.starts_with("%package ") || line == "%description" || line.starts_with("%prep") {
            flush_section_edges(&provides, &requires, edges);
            provides.clear();
            requires.clear();
            continue;
        }
        if let Some(payload) = regexes()
            .provides
            .captures(line)
            .and_then(|captures| captures.get(1))
        {
            if let Some(req) = parse_crate_requirement(&expand_macros(payload.as_str(), &macros)) {
                provides.push(req);
            }
        }
        if let Some(payload) = regexes()
            .requires
            .captures(line)
            .and_then(|captures| captures.get(1))
        {
            if let Some(req) = parse_crate_requirement(&expand_macros(payload.as_str(), &macros)) {
                requires.push(req);
            }
        }
    }
    flush_section_edges(&provides, &requires, edges);
    Ok(())
}

fn flush_section_edges(
    provides: &[Requirement],
    requires: &[Requirement],
    edges: &mut BTreeMap<String, Vec<Edge>>,
) {
    for provided in provides {
        for required in requires {
            edges.entry(provided.cap.clone()).or_default().push(Edge {
                to: required.clone(),
            });
        }
    }
}

fn add_simple_cargo_feature_graph_edges(
    cargo_toml: &Path,
    edges: &mut BTreeMap<String, Vec<Edge>>,
) -> Result<usize> {
    let content = fs::read_to_string(cargo_toml)
        .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
    let doc: toml::Value = toml::from_str(&content)
        .with_context(|| format!("failed to parse {}", cargo_toml.display()))?;
    let Some(package) = doc.get("package").and_then(|value| value.as_table()) else {
        return Ok(0);
    };
    let Some(crate_name) = package.get("name").and_then(|value| value.as_str()) else {
        return Ok(0);
    };
    let Some(version) = package.get("version").and_then(|value| value.as_str()) else {
        return Ok(0);
    };
    let Ok(version) = Version::parse(version) else {
        return Ok(0);
    };
    let pkgname = format!(
        "{}-{}",
        crate_name.replace('_', "-"),
        calculate_compat_version(&version)
    );
    let lower_bound = Some(version);

    let Some(features) = doc.get("features").and_then(|value| value.as_table()) else {
        return Ok(0);
    };

    let mut added = 0usize;
    for (feature, items) in features {
        let source = package_capability(&pkgname, Some(feature));
        let Some(items) = items.as_array() else {
            continue;
        };
        for item in items.iter().filter_map(|item| item.as_str()) {
            let Some(target_feature) = same_crate_feature_item(item) else {
                continue;
            };
            let target = Requirement {
                cap: package_capability(&pkgname, Some(&target_feature)),
                lower_bound: lower_bound.clone(),
                raw: format!(
                    "crate({})",
                    package_capability(&pkgname, Some(&target_feature))
                ),
            };
            edges
                .entry(source.clone())
                .or_default()
                .push(Edge { to: target });
            added += 1;
        }

        if feature == "default" {
            let target = Requirement {
                cap: package_capability(&pkgname, None),
                lower_bound: lower_bound.clone(),
                raw: format!("crate({pkgname})"),
            };
            edges.entry(source).or_default().push(Edge { to: target });
            added += 1;
        }
    }

    Ok(added)
}

fn compute_closure(roots: &[BuildReqRecord], graph: &CapabilityGraph) -> Closure {
    let mut closure = Closure::default();
    let mut queue = VecDeque::new();
    for root in roots {
        if add_lower_bound(
            &mut closure.lower_bounds,
            root.requirement.cap.clone(),
            root.requirement.lower_bound.clone(),
        ) {
            queue.push_back(root.requirement.cap.clone());
        }
    }

    while let Some(cap) = queue.pop_front() {
        let Some(outgoing) = graph.edges.get(&cap) else {
            continue;
        };
        for edge in outgoing {
            if add_lower_bound(
                &mut closure.lower_bounds,
                edge.to.cap.clone(),
                edge.to.lower_bound.clone(),
            ) {
                queue.push_back(edge.to.cap.clone());
            }
        }
    }

    closure
}

fn add_lower_bound(
    lower_bounds: &mut BTreeMap<String, Option<Version>>,
    cap: String,
    lower_bound: Option<Version>,
) -> bool {
    match lower_bounds.get_mut(&cap) {
        None => {
            lower_bounds.insert(cap, lower_bound);
            true
        }
        Some(existing) if lower_bound_is_stronger(&lower_bound, existing) => {
            *existing = lower_bound;
            true
        }
        _ => false,
    }
}

fn covers_requirement(state: Option<&Option<Version>>, requirement: &Requirement) -> bool {
    let Some(state) = state else {
        return false;
    };
    match (&requirement.lower_bound, state) {
        (None, _) => true,
        (Some(required), Some(implied)) => implied >= required,
        (Some(_), None) => false,
    }
}

fn missing_reason(requirement: &Requirement, closure: &Closure) -> String {
    match closure.lower_bounds.get(&requirement.cap) {
        None => "not implied by selected root BuildRequires".to_string(),
        Some(None) if requirement.lower_bound.is_some() => {
            "implied without a version, weaker than flattened lock-selected version".to_string()
        }
        Some(Some(implied)) => {
            format!("provider lower bound {implied} is weaker than flattened lock-selected version")
        }
        Some(None) => "not implied by selected root BuildRequires".to_string(),
    }
}

fn parse_buildrequires_lines(lines: &[String]) -> Vec<BuildReqRecord> {
    lines
        .iter()
        .filter_map(|line| {
            let payload = regexes()
                .build_requires
                .captures(line)
                .and_then(|captures| captures.get(1))
                .map(|matched| matched.as_str())
                .unwrap_or(line);
            parse_crate_requirement(payload).map(|requirement| BuildReqRecord {
                requirement,
                raw_line: line.clone(),
            })
        })
        .collect()
}

fn parse_crate_requirement(payload: &str) -> Option<Requirement> {
    let payload = payload.split('#').next().unwrap_or(payload).trim();
    let captures = regexes().crate_cap.captures(payload)?;
    let cap = captures.get(1)?.as_str().to_string();
    let lower_bound = captures
        .get(3)
        .and_then(|version| Version::parse(version.as_str()).ok());
    Some(Requirement {
        cap,
        lower_bound,
        raw: payload.to_string(),
    })
}

fn define_macro(rest: &str, macros: &mut BTreeMap<String, String>) {
    let mut parts = rest.splitn(2, char::is_whitespace);
    let Some(key) = parts.next() else {
        return;
    };
    let Some(value) = parts.next() else {
        return;
    };
    macros.insert(key.to_string(), value.trim().to_string());
}

fn expand_macros(text: &str, macros: &BTreeMap<String, String>) -> String {
    let mut expanded = text.to_string();
    for _ in 0..8 {
        let next = regexes()
            .macro_ref
            .replace_all(&expanded, |captures: &regex::Captures<'_>| {
                macros
                    .get(
                        captures
                            .get(1)
                            .map(|matched| matched.as_str())
                            .unwrap_or(""),
                    )
                    .cloned()
                    .unwrap_or_else(|| captures.get(0).unwrap().as_str().to_string())
            })
            .to_string();
        if next == expanded {
            break;
        }
        expanded = next;
    }
    expanded
}

fn same_crate_feature_item(item: &str) -> Option<String> {
    if item.starts_with("dep:") || item.contains('/') {
        return None;
    }
    Some(normalize_feature_name(item))
}

fn package_capability(pkgname: &str, feature: Option<&str>) -> String {
    match feature {
        Some(feature) => format!("{}/{}", pkgname, normalize_feature_name(feature)),
        None => pkgname.to_string(),
    }
}

fn capability_package_key(capability: &str) -> String {
    capability
        .split('/')
        .next()
        .unwrap_or(capability)
        .to_string()
}

fn lower_bound_is_stronger(candidate: &Option<Version>, current: &Option<Version>) -> bool {
    match (candidate, current) {
        (Some(candidate), Some(current)) => candidate > current,
        (Some(_), None) => true,
        _ => false,
    }
}

fn ruyispec_specs_root(ruyispec_root: &Path) -> PathBuf {
    let specs = ruyispec_root.join("SPECS");
    if specs.is_dir() {
        specs
    } else {
        ruyispec_root.to_path_buf()
    }
}

fn sorted_read_dir(path: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = fs::read_dir(path)
        .with_context(|| format!("failed to read directory {}", path.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()
        .with_context(|| format!("failed to read directory entry under {}", path.display()))?;
    paths.sort();
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_provider(root: &Path, dir: &str, name: &str, content: &str) {
        let provider_dir = root.join("SPECS").join(dir);
        fs::create_dir_all(&provider_dir).unwrap();
        fs::write(provider_dir.join(name), content).unwrap();
    }

    #[test]
    fn validation_reports_missing_flattened_requirements() {
        let temp = tempfile::tempdir().unwrap();
        write_provider(
            temp.path(),
            "rust-foo-1",
            "rust-foo-1.spec",
            r#"%package -n rust-foo-1+default
Provides: crate(foo-1/default) >= 1.0.0
Requires: crate(bar-1/default) >= 1.0.0
"#,
        );

        let roots = vec!["BuildRequires: crate(foo-1/default) >= 1.0.0".to_string()];
        let flattened = vec![
            "BuildRequires: crate(foo-1/default) >= 1.0.0".to_string(),
            "BuildRequires: crate(bar-1/default) >= 1.0.0".to_string(),
            "BuildRequires: crate(baz-1/default) >= 1.0.0".to_string(),
        ];

        let report = validate_buildrequires_closure(&roots, &flattened, temp.path()).unwrap();
        assert_eq!(report.flattened_requirements, 3);
        assert_eq!(report.covered_flattened_requirements, 2);
        assert_eq!(report.missing_flattened_requirements, 1);
        assert_eq!(
            report
                .missing_by_package
                .get("baz-1")
                .map(|items| items.len())
                .unwrap_or_default(),
            1
        );
    }

    #[test]
    fn cargo_feature_graph_expands_same_crate_features() {
        let temp = tempfile::tempdir().unwrap();
        let provider_dir = temp.path().join("SPECS").join("rust-foo-1");
        fs::create_dir_all(&provider_dir).unwrap();
        fs::write(
            provider_dir.join("Cargo.toml"),
            r#"[package]
name = "foo"
version = "1.0.0"

[features]
default = ["std"]
std = []
"#,
        )
        .unwrap();

        let roots = vec!["BuildRequires: crate(foo-1/default) >= 1.0.0".to_string()];
        let flattened = vec![
            "BuildRequires: crate(foo-1/default) >= 1.0.0".to_string(),
            "BuildRequires: crate(foo-1/std) >= 1.0.0".to_string(),
            "BuildRequires: crate(foo-1) >= 1.0.0".to_string(),
        ];

        let report = validate_buildrequires_closure(&roots, &flattened, temp.path()).unwrap();
        assert_eq!(report.missing_flattened_requirements, 0);
        assert_eq!(report.provider_cargo_feature_edges_added, 2);
    }
}
