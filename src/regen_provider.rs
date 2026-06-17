//! Regenerate an existing provider directory without losing source metadata.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use toml_edit::{value, DocumentMut, Item, Value};
use walkdir::WalkDir;

use crate::local_package::process_local_package;
use crate::package::PackageExecuteArgs;
use crate::range_audit::RangeCapabilityPolicy;

pub fn regenerate_provider(
    provider_dir: &Path,
    output_dir: &Path,
    base_cargo_toml: Option<&Path>,
    range_capability_policy: RangeCapabilityPolicy,
) -> Result<()> {
    let provider_dir = provider_dir
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", provider_dir.display()))?;
    if !provider_dir.is_dir() {
        anyhow::bail!(
            "existing provider path is not a directory: {}",
            provider_dir.display()
        );
    }

    let source_cargo_toml = provider_dir.join("Cargo.toml");
    if !source_cargo_toml.is_file() {
        anyhow::bail!("Cargo.toml not found in {}", provider_dir.display());
    }

    let output_dir = absolute_output_path(output_dir)?;
    reject_output_over_input(&provider_dir, &output_dir)?;

    let old_spec = find_spec_file(&provider_dir)
        .ok_or_else(|| anyhow::anyhow!("no .spec file found in {}", provider_dir.display()))?;
    let old_spec_content = fs::read_to_string(&old_spec)
        .with_context(|| format!("failed to read {}", old_spec.display()))?;

    process_local_package(
        &provider_dir,
        Some(output_dir.clone()),
        default_package_execute_args(),
        range_capability_policy,
    )?;

    copy_provider_payload(&provider_dir, &output_dir)?;

    let patch_file_name = maybe_write_cargo_toml_patch(
        &provider_dir,
        &output_dir,
        base_cargo_toml,
        &old_spec_content,
    )?;

    let new_spec = find_spec_file(&output_dir).ok_or_else(|| {
        anyhow::anyhow!(
            "regenerated provider did not create a .spec file in {}",
            output_dir.display()
        )
    })?;
    let new_spec_content = fs::read_to_string(&new_spec)
        .with_context(|| format!("failed to read {}", new_spec.display()))?;
    let merged_spec = merge_spec_source_metadata(
        &new_spec_content,
        &old_spec_content,
        patch_file_name.as_deref(),
    );
    fs::write(&new_spec, merged_spec)
        .with_context(|| format!("failed to write {}", new_spec.display()))?;

    println!("Regenerated provider: {}", output_dir.display());
    Ok(())
}

fn default_package_execute_args() -> PackageExecuteArgs {
    PackageExecuteArgs {
        changelog_ready: false,
        copyright_guess_harder: false,
        no_overlay_write_back: false,
        lockfile_deps: None,
    }
}

fn absolute_output_path(output_dir: &Path) -> Result<PathBuf> {
    if output_dir.exists() {
        return output_dir
            .canonicalize()
            .with_context(|| format!("failed to resolve {}", output_dir.display()));
    }
    if output_dir.is_absolute() {
        Ok(output_dir.to_path_buf())
    } else {
        Ok(std::env::current_dir()
            .context("failed to read current directory")?
            .join(output_dir))
    }
}

fn reject_output_over_input(provider_dir: &Path, output_dir: &Path) -> Result<()> {
    if output_dir == provider_dir {
        anyhow::bail!("refusing to overwrite input provider directory");
    }
    if output_dir.starts_with(provider_dir) {
        anyhow::bail!(
            "refusing to write output {} inside input provider {}",
            output_dir.display(),
            provider_dir.display()
        );
    }
    Ok(())
}

fn find_spec_file(dir: &Path) -> Option<PathBuf> {
    let mut specs = fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "spec"))
        .collect::<Vec<_>>();
    specs.sort();
    specs.into_iter().next()
}

fn copy_provider_payload(provider_dir: &Path, output_dir: &Path) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create {}", output_dir.display()))?;

    for entry in fs::read_dir(provider_dir)
        .with_context(|| format!("failed to read {}", provider_dir.display()))?
    {
        let entry = entry?;
        let source = entry.path();
        let file_name = entry.file_name();
        if should_skip_provider_payload(&source) {
            continue;
        }
        let dest = output_dir.join(file_name);
        copy_path(&source, &dest)?;
    }

    Ok(())
}

fn should_skip_provider_payload(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "Cargo.toml")
        || path.extension().is_some_and(|ext| ext == "spec")
}

fn copy_path(source: &Path, dest: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("failed to stat {}", source.display()))?;
    if metadata.is_dir() {
        copy_dir_recursive(source, dest)
    } else if metadata.file_type().is_symlink() {
        copy_symlink(source, dest)
    } else {
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        fs::copy(source, dest).with_context(|| {
            format!("failed to copy {} to {}", source.display(), dest.display())
        })?;
        Ok(())
    }
}

fn copy_dir_recursive(source: &Path, dest: &Path) -> Result<()> {
    for entry in WalkDir::new(source) {
        let entry = entry.with_context(|| format!("failed to walk {}", source.display()))?;
        let path = entry.path();
        let rel = path
            .strip_prefix(source)
            .with_context(|| format!("{} is not under {}", path.display(), source.display()))?;
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)
                .with_context(|| format!("failed to create {}", target.display()))?;
        } else if entry.file_type().is_symlink() {
            copy_symlink(path, &target)?;
        } else {
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

#[cfg(unix)]
fn copy_symlink(source: &Path, dest: &Path) -> Result<()> {
    use std::os::unix::fs::symlink;

    if dest.exists() || fs::symlink_metadata(dest).is_ok() {
        let _ = fs::remove_file(dest);
    }
    let target =
        fs::read_link(source).with_context(|| format!("failed to read {}", source.display()))?;
    symlink(&target, dest).with_context(|| {
        format!(
            "failed to symlink {} to {}",
            target.display(),
            dest.display()
        )
    })
}

#[cfg(not(unix))]
fn copy_symlink(source: &Path, dest: &Path) -> Result<()> {
    let target =
        fs::read_link(source).with_context(|| format!("failed to read {}", source.display()))?;
    let resolved = source
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(target);
    copy_path(&resolved, dest)
}

fn maybe_write_cargo_toml_patch(
    provider_dir: &Path,
    output_dir: &Path,
    base_cargo_toml: Option<&Path>,
    old_spec: &str,
) -> Result<Option<String>> {
    let target_cargo_toml =
        fs::read_to_string(provider_dir.join("Cargo.toml")).with_context(|| {
            format!(
                "failed to read {}",
                provider_dir.join("Cargo.toml").display()
            )
        })?;
    let patch_specs = SpecMetadata::parse(old_spec).patch_specs();
    let Some(prepared) = prepare_patch_base(provider_dir, base_cargo_toml, &patch_specs)? else {
        eprintln!(
            "warning: unable to prepare patched source Cargo.toml for {}; no Cargo.toml patch generated",
            provider_dir.display()
        );
        return Ok(None);
    };

    let updated = update_dependency_versions(&prepared.cargo_toml_content, &target_cargo_toml)?;
    if updated == prepared.cargo_toml_content {
        return Ok(None);
    }

    let next_patch = next_patch_index(
        &patch_specs
            .iter()
            .map(|patch| patch.line.clone())
            .collect::<Vec<_>>(),
    );
    let patch_name = choose_cargo_patch_name(output_dir, next_patch);
    let patch =
        unified_cargo_toml_diff(prepared.cargo_toml_content.as_bytes(), updated.as_bytes())?;
    let patch_path = output_dir.join(&patch_name);
    fs::write(&patch_path, patch)
        .with_context(|| format!("failed to write {}", patch_path.display()))?;
    dry_run_patch(&prepared.source_root, &patch_path)?;
    Ok(Some(patch_name))
}

fn read_base_cargo_toml(
    provider_dir: &Path,
    base_cargo_toml: Option<&Path>,
) -> Result<Option<Vec<u8>>> {
    if let Some(base_cargo_toml) = base_cargo_toml {
        return fs::read(base_cargo_toml)
            .with_context(|| format!("failed to read {}", base_cargo_toml.display()))
            .map(Some);
    }

    git_head_cargo_toml(provider_dir)
}

fn git_head_cargo_toml(provider_dir: &Path) -> Result<Option<Vec<u8>>> {
    let top = Command::new("git")
        .arg("-C")
        .arg(provider_dir)
        .args(["rev-parse", "--show-toplevel"])
        .output();
    let Ok(top) = top else {
        return Ok(None);
    };
    if !top.status.success() {
        return Ok(None);
    }

    let top = String::from_utf8_lossy(&top.stdout).trim().to_string();
    if top.is_empty() {
        return Ok(None);
    }
    let top = PathBuf::from(top);
    let cargo_toml = provider_dir.join("Cargo.toml").canonicalize()?;
    let top_canon = top.canonicalize()?;
    let rel = cargo_toml
        .strip_prefix(&top_canon)
        .with_context(|| format!("{} is not under {}", cargo_toml.display(), top.display()))?;
    let rel = rel.to_string_lossy().replace('\\', "/");

    let show = Command::new("git")
        .arg("-C")
        .arg(&top)
        .arg("show")
        .arg(format!("HEAD:{rel}"))
        .output()
        .with_context(|| format!("failed to execute git show for {rel}"))?;
    if !show.status.success() {
        return Ok(None);
    }

    Ok(Some(show.stdout))
}

#[derive(Debug, Clone)]
struct PatchSpec {
    line: String,
    file_name: String,
}

struct PreparedPatchBase {
    _tempdir: tempfile::TempDir,
    source_root: PathBuf,
    cargo_toml_content: String,
}

fn prepare_patch_base(
    provider_dir: &Path,
    base_cargo_toml: Option<&Path>,
    patch_specs: &[PatchSpec],
) -> Result<Option<PreparedPatchBase>> {
    if let Some(source_archive) = find_local_source_archive(provider_dir)? {
        let tempdir = tempfile::tempdir().context("failed to create source extraction tempdir")?;
        extract_source_archive(&source_archive, tempdir.path())
            .with_context(|| format!("failed to extract {}", source_archive.display()))?;
        let source_root = find_source_root_with_cargo_toml(tempdir.path()).ok_or_else(|| {
            anyhow::anyhow!(
                "source archive {} did not contain Cargo.toml",
                source_archive.display()
            )
        })?;
        apply_existing_patches(provider_dir, &source_root, patch_specs)?;
        let cargo_toml = source_root.join("Cargo.toml");
        let cargo_toml_content = fs::read_to_string(&cargo_toml)
            .with_context(|| format!("failed to read {}", cargo_toml.display()))?;
        return Ok(Some(PreparedPatchBase {
            _tempdir: tempdir,
            source_root,
            cargo_toml_content,
        }));
    }

    let Some(base) = read_base_cargo_toml(provider_dir, base_cargo_toml)? else {
        return Ok(None);
    };

    let tempdir = tempfile::tempdir().context("failed to create Cargo.toml patch tempdir")?;
    let source_root = tempdir.path().join("source");
    fs::create_dir_all(&source_root)
        .with_context(|| format!("failed to create {}", source_root.display()))?;
    fs::write(source_root.join("Cargo.toml"), base).with_context(|| {
        format!(
            "failed to write {}",
            source_root.join("Cargo.toml").display()
        )
    })?;

    if let Err(err) = apply_existing_patches(provider_dir, &source_root, patch_specs) {
        eprintln!(
            "warning: unable to validate/apply existing Patch chain against Cargo.toml-only base: {err:#}"
        );
        return Ok(None);
    }

    let cargo_toml_content =
        fs::read_to_string(source_root.join("Cargo.toml")).with_context(|| {
            format!(
                "failed to read {}",
                source_root.join("Cargo.toml").display()
            )
        })?;
    Ok(Some(PreparedPatchBase {
        _tempdir: tempdir,
        source_root,
        cargo_toml_content,
    }))
}

fn find_local_source_archive(provider_dir: &Path) -> Result<Option<PathBuf>> {
    let spec = find_spec_file(provider_dir);
    if let Some(spec) = spec {
        let spec_content = fs::read_to_string(&spec)
            .with_context(|| format!("failed to read {}", spec.display()))?;
        let metadata = SpecMetadata::parse(&spec_content);
        for source_line in metadata.source_lines {
            if let Some(candidate) = source_path_from_line(provider_dir, &source_line) {
                if candidate.is_file() && is_supported_source_archive(&candidate) {
                    return Ok(Some(candidate));
                }
            }
        }
    }

    let mut archives = fs::read_dir(provider_dir)
        .with_context(|| format!("failed to read {}", provider_dir.display()))?
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && is_supported_source_archive(path))
        .collect::<Vec<_>>();
    archives.sort();
    Ok(archives.into_iter().next())
}

fn source_path_from_line(provider_dir: &Path, line: &str) -> Option<PathBuf> {
    let (_, value) = line.split_once(':')?;
    let token = value.trim().split_whitespace().next()?.trim_matches('"');
    let file_name = token
        .split_once("#/")
        .map(|(_, suffix)| suffix)
        .unwrap_or(token)
        .rsplit('/')
        .next()
        .unwrap_or(token);
    if file_name.contains('%') || file_name.is_empty() {
        return None;
    }
    Some(provider_dir.join(file_name))
}

fn is_supported_source_archive(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    name.ends_with(".tar.gz") || name.ends_with(".tgz") || name.ends_with(".tar")
}

fn extract_source_archive(archive_path: &Path, dest: &Path) -> Result<()> {
    let file = fs::File::open(archive_path)
        .with_context(|| format!("failed to open {}", archive_path.display()))?;
    let name = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        let reader: Box<dyn Read> = Box::new(GzDecoder::new(file));
        let mut archive = tar::Archive::new(reader);
        archive.unpack(dest)?;
    } else {
        let reader: Box<dyn Read> = Box::new(file);
        let mut archive = tar::Archive::new(reader);
        archive.unpack(dest)?;
    }
    Ok(())
}

fn find_source_root_with_cargo_toml(root: &Path) -> Option<PathBuf> {
    let mut manifests = WalkDir::new(root)
        .into_iter()
        .flatten()
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == "Cargo.toml")
        .map(|entry| entry.path().to_path_buf())
        .collect::<Vec<_>>();
    manifests.sort_by_key(|path| path.components().count());
    manifests
        .into_iter()
        .next()
        .and_then(|manifest| manifest.parent().map(Path::to_path_buf))
}

fn apply_existing_patches(
    provider_dir: &Path,
    source_root: &Path,
    patch_specs: &[PatchSpec],
) -> Result<()> {
    for patch in patch_specs {
        let patch_path = provider_dir.join(&patch.file_name);
        apply_patch(source_root, &patch_path)?;
    }
    Ok(())
}

fn apply_patch(source_root: &Path, patch_path: &Path) -> Result<()> {
    run_patch_command(source_root, patch_path, false)
}

fn dry_run_patch(source_root: &Path, patch_path: &Path) -> Result<()> {
    run_patch_command(source_root, patch_path, true)
}

fn run_patch_command(source_root: &Path, patch_path: &Path, dry_run: bool) -> Result<()> {
    if !patch_path.is_file() {
        anyhow::bail!("patch file not found: {}", patch_path.display());
    }
    let mut command = Command::new("patch");
    command
        .current_dir(source_root)
        .args(["-p1", "--batch", "--forward", "-i"])
        .arg(patch_path);
    if dry_run {
        command.arg("--dry-run");
    }
    let output = command.output().with_context(|| {
        format!(
            "failed to execute patch for {} in {}",
            patch_path.display(),
            source_root.display()
        )
    })?;
    if !output.status.success() {
        anyhow::bail!(
            "{} patch {} failed in {}:\n{}{}",
            if dry_run { "dry-run" } else { "apply" },
            patch_path.display(),
            source_root.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn choose_cargo_patch_name(output_dir: &Path, patch_index: usize) -> String {
    for index in (patch_index + 1).. {
        let candidate = format!("{index:04}-fix-range-dependencies.patch");
        if !output_dir.join(&candidate).exists() {
            return candidate;
        }
    }
    unreachable!("unbounded patch name search should find a candidate")
}

fn unified_cargo_toml_diff(base: &[u8], current: &[u8]) -> Result<String> {
    let tmp = tempfile::tempdir().context("failed to create diff tempdir")?;
    let base_path = tmp.path().join("Cargo.toml.base");
    let current_path = tmp.path().join("Cargo.toml.current");
    fs::write(&base_path, base).context("failed to write base Cargo.toml for diff")?;
    fs::write(&current_path, current).context("failed to write current Cargo.toml for diff")?;

    let output = Command::new("diff")
        .args(["-u", "--label", "a/Cargo.toml", "--label", "b/Cargo.toml"])
        .arg(&base_path)
        .arg(&current_path)
        .output()
        .context("failed to execute diff")?;

    match output.status.code() {
        Some(0) => Ok(String::new()),
        Some(1) => Ok(String::from_utf8_lossy(&output.stdout).to_string()),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("diff failed: {}", stderr.trim());
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct DependencyVersion {
    path: Vec<String>,
    name: String,
    version: String,
}

fn update_dependency_versions(source_cargo_toml: &str, target_cargo_toml: &str) -> Result<String> {
    let targets = collect_dependency_versions(target_cargo_toml)?;
    let mut source_doc = source_cargo_toml
        .parse::<DocumentMut>()
        .context("failed to parse source Cargo.toml")?;
    let mut changed = false;

    for target in targets {
        if update_dependency_version(&mut source_doc, &target)? {
            changed = true;
        }
    }

    if changed {
        Ok(source_doc.to_string())
    } else {
        Ok(source_cargo_toml.to_string())
    }
}

fn collect_dependency_versions(cargo_toml: &str) -> Result<Vec<DependencyVersion>> {
    let doc = cargo_toml
        .parse::<DocumentMut>()
        .context("failed to parse target Cargo.toml")?;
    let mut versions = Vec::new();

    for section in ["dependencies", "build-dependencies", "dev-dependencies"] {
        collect_dependency_versions_from_section(doc.as_table(), &[section], &mut versions);
    }

    if let Some(targets) = doc.as_table().get("target").and_then(Item::as_table) {
        for (target_name, target_item) in targets.iter() {
            if target_item.as_table().is_none() {
                continue;
            }
            for section in ["dependencies", "build-dependencies", "dev-dependencies"] {
                collect_dependency_versions_from_section(
                    doc.as_table(),
                    &["target", target_name, section],
                    &mut versions,
                );
            }
        }
    }

    Ok(versions)
}

fn collect_dependency_versions_from_section(
    table: &toml_edit::Table,
    path: &[&str],
    out: &mut Vec<DependencyVersion>,
) {
    let Some(dep_table) = table_at_path(table, path) else {
        return;
    };
    for (name, item) in dep_table.iter() {
        if let Some(version) = dependency_version_from_item(item) {
            out.push(DependencyVersion {
                path: path.iter().map(|part| (*part).to_string()).collect(),
                name: name.to_string(),
                version,
            });
        }
    }
}

fn table_at_path<'a>(table: &'a toml_edit::Table, path: &[&str]) -> Option<&'a toml_edit::Table> {
    let mut current = table;
    for part in path {
        current = current.get(*part)?.as_table()?;
    }
    Some(current)
}

fn dependency_version_from_item(item: &Item) -> Option<String> {
    if let Some(version) = item.as_str() {
        return Some(version.to_string());
    }
    if let Some(table) = item.as_table() {
        return table
            .get("version")
            .and_then(Item::as_str)
            .map(str::to_string);
    }
    if let Some(value) = item.as_value() {
        if let Value::InlineTable(table) = value {
            return table
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string);
        }
    }
    None
}

fn update_dependency_version(
    source_doc: &mut DocumentMut,
    target: &DependencyVersion,
) -> Result<bool> {
    let path = target.path.iter().map(String::as_str).collect::<Vec<_>>();
    let Some(dep_table) = table_at_path_mut(source_doc.as_table_mut(), &path) else {
        return Ok(false);
    };
    let Some(item) = dep_table.get_mut(&target.name) else {
        return Ok(false);
    };
    set_dependency_version(item, &target.version)
}

fn table_at_path_mut<'a>(
    table: &'a mut toml_edit::Table,
    path: &[&str],
) -> Option<&'a mut toml_edit::Table> {
    let mut current = table;
    for part in path {
        current = current.get_mut(*part)?.as_table_mut()?;
    }
    Some(current)
}

fn set_dependency_version(item: &mut Item, version: &str) -> Result<bool> {
    if let Some(current) = item.as_str() {
        if current == version {
            return Ok(false);
        }
        *item = value(version);
        return Ok(true);
    }

    if let Some(table) = item.as_table_mut() {
        let current = table.get("version").and_then(Item::as_str);
        if current == Some(version) {
            return Ok(false);
        }
        table["version"] = value(version);
        return Ok(true);
    }

    if let Some(value) = item.as_value_mut() {
        if let Value::InlineTable(table) = value {
            let current = table.get("version").and_then(Value::as_str);
            if current == Some(version) {
                return Ok(false);
            }
            table.insert("version", Value::from(version));
            return Ok(true);
        }
    }

    Ok(false)
}

fn merge_spec_source_metadata(
    new_spec: &str,
    old_spec: &str,
    cargo_patch_file: Option<&str>,
) -> String {
    let new_metadata = SpecMetadata::parse(new_spec);
    let old_metadata = SpecMetadata::parse(old_spec);

    let remote_asset_lines = if old_metadata.remote_asset_lines.is_empty() {
        new_metadata.remote_asset_lines
    } else {
        old_metadata.remote_asset_lines
    };
    let source_lines = if old_metadata.source_lines.is_empty() {
        new_metadata.source_lines
    } else {
        old_metadata.source_lines
    };
    let mut patch_lines = old_metadata.patch_lines;
    if let Some(cargo_patch_file) = cargo_patch_file {
        let next = next_patch_index(&patch_lines);
        patch_lines.push(format!("Patch{next}:         {cargo_patch_file}"));
    }

    let has_build_system = new_spec
        .lines()
        .any(|line| line.trim_start().starts_with("BuildSystem:"));
    if !has_build_system && !patch_lines.is_empty() {
        eprintln!(
            "warning: regenerated spec has no BuildSystem line; inserting Patch metadata at source metadata position"
        );
    }

    let mut merged = Vec::new();
    let mut source_inserted = false;
    let mut patches_inserted = false;
    let mut skip_blank_after_patch_insertion = false;
    for line in new_spec.lines() {
        if skip_blank_after_patch_insertion && line.trim().is_empty() {
            skip_blank_after_patch_insertion = false;
            continue;
        }
        skip_blank_after_patch_insertion = false;

        if is_remote_asset_or_source_line(line) || is_patch_line(line) {
            if !source_inserted {
                push_source_metadata_lines(&mut merged, &remote_asset_lines, &source_lines);
                source_inserted = true;
                if !has_build_system {
                    push_patch_lines(&mut merged, &patch_lines);
                    patches_inserted = true;
                }
            }
            continue;
        }

        if !source_inserted
            && (line.trim_start().starts_with("BuildArch:")
                || line.trim_start().starts_with("BuildSystem:")
                || line.trim_start().starts_with("BuildRequires:"))
        {
            push_source_metadata_lines(&mut merged, &remote_asset_lines, &source_lines);
            source_inserted = true;
            if !has_build_system {
                push_patch_lines(&mut merged, &patch_lines);
                patches_inserted = true;
            }
        }

        let is_build_system = line.trim_start().starts_with("BuildSystem:");
        merged.push(line.to_string());

        if is_build_system && !patches_inserted {
            push_patch_block_after_build_system(&mut merged, &patch_lines);
            patches_inserted = true;
            skip_blank_after_patch_insertion = !patch_lines.is_empty();
        }
    }

    if !source_inserted {
        let mut prefixed = Vec::new();
        push_source_metadata_lines(&mut prefixed, &remote_asset_lines, &source_lines);
        if !has_build_system && !patches_inserted {
            push_patch_lines(&mut prefixed, &patch_lines);
            patches_inserted = true;
        }
        prefixed.extend(merged);
        merged = prefixed;
    }

    if !patches_inserted && !patch_lines.is_empty() {
        if let Some(index) = merged
            .iter()
            .position(|line| line.trim_start().starts_with("BuildSystem:"))
        {
            let mut rebuilt = Vec::with_capacity(merged.len() + patch_lines.len() + 2);
            for (line_index, line) in merged.into_iter().enumerate() {
                rebuilt.push(line);
                if line_index == index {
                    push_patch_block_after_build_system(&mut rebuilt, &patch_lines);
                }
            }
            merged = rebuilt;
        } else {
            eprintln!(
                "warning: regenerated spec has no BuildSystem line; appending Patch metadata before BuildRequires"
            );
            let build_requires_index = merged
                .iter()
                .position(|line| line.trim_start().starts_with("BuildRequires:"));
            if let Some(index) = build_requires_index {
                let mut rebuilt = Vec::with_capacity(merged.len() + patch_lines.len());
                for (line_index, line) in merged.into_iter().enumerate() {
                    if line_index == index {
                        push_patch_lines(&mut rebuilt, &patch_lines);
                    }
                    rebuilt.push(line);
                }
                merged = rebuilt;
            } else {
                push_patch_lines(&mut merged, &patch_lines);
            }
        }
    }

    let mut rendered = merged.join("\n");
    rendered.push('\n');
    rendered
}

fn push_source_metadata_lines(
    out: &mut Vec<String>,
    remote_asset_lines: &[String],
    source_lines: &[String],
) {
    out.extend(remote_asset_lines.iter().cloned());
    out.extend(source_lines.iter().cloned());
}

fn push_patch_block_after_build_system(out: &mut Vec<String>, patch_lines: &[String]) {
    if patch_lines.is_empty() {
        return;
    }
    out.push(String::new());
    push_patch_lines(out, patch_lines);
    out.push(String::new());
}

fn push_patch_lines(out: &mut Vec<String>, patch_lines: &[String]) {
    out.extend(patch_lines.iter().cloned());
}

#[derive(Debug, Default)]
struct SpecMetadata {
    remote_asset_lines: Vec<String>,
    source_lines: Vec<String>,
    patch_lines: Vec<String>,
}

impl SpecMetadata {
    fn parse(spec: &str) -> Self {
        let mut metadata = Self::default();
        for line in spec.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("#!RemoteAsset:") {
                metadata.remote_asset_lines.push(line.to_string());
            } else if spec_tag_matches(trimmed, "Source") {
                metadata.source_lines.push(line.to_string());
            } else if spec_tag_matches(trimmed, "Patch") {
                metadata.patch_lines.push(line.to_string());
            }
        }
        metadata
    }

    fn patch_specs(&self) -> Vec<PatchSpec> {
        self.patch_lines
            .iter()
            .filter_map(|line| {
                let (_, value) = line.split_once(':')?;
                let file_name = value.trim().split_whitespace().next()?.trim_matches('"');
                if file_name.is_empty() {
                    return None;
                }
                Some(PatchSpec {
                    line: line.clone(),
                    file_name: file_name.to_string(),
                })
            })
            .collect()
    }
}

fn is_remote_asset_or_source_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("#!RemoteAsset:") || spec_tag_matches(trimmed, "Source")
}

fn is_patch_line(line: &str) -> bool {
    spec_tag_matches(line.trim_start(), "Patch")
}

fn spec_tag_matches(line: &str, prefix: &str) -> bool {
    let Some((tag, _)) = line.split_once(':') else {
        return false;
    };
    tag == prefix
        || tag.strip_prefix(prefix).is_some_and(|suffix| {
            !suffix.is_empty() && suffix.chars().all(|ch| ch.is_ascii_digit())
        })
}

fn next_patch_index(patch_lines: &[String]) -> usize {
    let mut next = 0usize;
    for line in patch_lines {
        let Some((tag, _)) = line.trim_start().split_once(':') else {
            continue;
        };
        let Some(suffix) = tag.strip_prefix("Patch") else {
            continue;
        };
        let index = if suffix.is_empty() {
            0
        } else {
            suffix.parse::<usize>().unwrap_or(0)
        };
        next = next.max(index + 1);
    }
    next
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use tar::{Builder, Header};

    #[test]
    fn merge_preserves_old_source_metadata_and_appends_patch() {
        let old_spec = r#"%global crate_name demo
URL:            https://example.invalid
#!RemoteAsset:  sha256:old
Source0:        https://example.invalid/demo.tar.gz
Patch0:         old.patch
BuildArch:      noarch

Requires:       crate(old-1)
"#;
        let new_spec = r#"%global crate_name demo
URL:            https://example.invalid
#!RemoteAsset:  sha256:
Source:         https://static.crates.io/crates/demo/1.0.0/download#/%{name}-%{version}.tar.gz
BuildArch:      noarch
BuildSystem:    rustcrates

BuildRequires:  rust-rpm-macros
Requires:       crate(new-1)
"#;

        let merged = merge_spec_source_metadata(
            new_spec,
            old_spec,
            Some("0002-fix-range-dependencies.patch"),
        );

        assert!(merged.contains("#!RemoteAsset:  sha256:old"));
        assert!(merged.contains("Source0:        https://example.invalid/demo.tar.gz"));
        assert!(merged.contains("Patch0:         old.patch"));
        assert!(merged.contains("Patch1:         0002-fix-range-dependencies.patch"));
        assert!(merged.contains("Requires:       crate(new-1)"));
        assert!(!merged.contains("sha256:\nSource:         https://static.crates.io"));
        assert!(!merged.contains("Requires:       crate(old-1)"));

        let build_arch = line_index(&merged, "BuildArch:").unwrap();
        let build_system = line_index(&merged, "BuildSystem:").unwrap();
        let patch0 = line_index(&merged, "Patch0:").unwrap();
        let patch1 = line_index(&merged, "Patch1:").unwrap();
        let build_requires = line_index(&merged, "BuildRequires:").unwrap();
        assert!(build_arch < build_system);
        assert!(build_system < patch0);
        assert!(patch0 < patch1);
        assert!(patch1 < build_requires);
        assert!(merged.contains(
            "BuildSystem:    rustcrates\n\nPatch0:         old.patch\nPatch1:         0002-fix-range-dependencies.patch\n\nBuildRequires:"
        ));
    }

    #[test]
    fn merge_adds_first_patch_when_old_spec_has_none() {
        let old_spec = r#"URL:            https://example.invalid
#!RemoteAsset:  sha256:old
Source:         old-source
"#;
        let new_spec = r#"URL:            https://example.invalid
#!RemoteAsset:  sha256:
Source:         new-source
BuildArch:      noarch
BuildSystem:    rustcrates
"#;

        let merged = merge_spec_source_metadata(new_spec, old_spec, Some("0001.patch"));

        assert!(merged.contains("Patch0:         0001.patch"));
        assert!(
            line_index(&merged, "BuildSystem:").unwrap() < line_index(&merged, "Patch0:").unwrap()
        );
    }

    #[test]
    fn chooses_unused_patch_name() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("0001-fix-range-dependencies.patch"), "").unwrap();

        assert_eq!(
            choose_cargo_patch_name(temp.path(), 0),
            "0002-fix-range-dependencies.patch"
        );
    }

    #[test]
    fn patch_generation_collects_multiple_dependency_changes_once() {
        let fixture = RegenFixture::new();
        fixture.write_source_archive(BASE_CARGO);
        fixture.write_patch("old-fix.patch", BASE_CARGO, PATCH0_CARGO);
        fixture.write_provider_cargo_toml(PATCH0_PLUS_BAR_BAZ_CARGO);
        fixture.write_output_payload(&["old-fix.patch"]);
        let old_spec = fixture.spec(&["Patch0:         old-fix.patch"]);

        let patch_name = maybe_write_cargo_toml_patch(
            fixture.provider.path(),
            fixture.output.path(),
            None,
            &old_spec,
        )
        .unwrap()
        .unwrap();

        assert_eq!(patch_name, "0002-fix-range-dependencies.patch");
        let patch = fs::read_to_string(fixture.output.path().join(&patch_name)).unwrap();
        assert!(patch.contains("+version = \"0.8.9\""));
        assert!(patch.contains("+version = \"0.0.6\""));
        assert!(!patch.contains("+version = \"1.2.3\""));

        let merged = merge_spec_source_metadata(&fixture.new_spec(), &old_spec, Some(&patch_name));
        assert!(merged.contains("Patch0:         old-fix.patch"));
        assert!(merged.contains("Patch1:         0002-fix-range-dependencies.patch"));
        assert!(
            line_index(&merged, "BuildSystem:").unwrap() < line_index(&merged, "Patch0:").unwrap()
        );
        assert!(
            line_index(&merged, "Patch1:").unwrap()
                < line_index(&merged, "BuildRequires:").unwrap()
        );
    }

    #[test]
    fn second_regen_without_new_dependency_changes_is_idempotent() {
        let fixture = RegenFixture::new();
        fixture.write_source_archive(BASE_CARGO);
        fixture.write_patch("old-fix.patch", BASE_CARGO, PATCH0_CARGO);
        fixture.write_patch(
            "0002-fix-range-dependencies.patch",
            PATCH0_CARGO,
            PATCH0_PLUS_BAR_BAZ_CARGO,
        );
        fixture.write_provider_cargo_toml(PATCH0_PLUS_BAR_BAZ_CARGO);
        fixture.write_output_payload(&["old-fix.patch", "0002-fix-range-dependencies.patch"]);
        let old_spec = fixture.spec(&[
            "Patch0:         old-fix.patch",
            "Patch1:         0002-fix-range-dependencies.patch",
        ]);

        let patch_name = maybe_write_cargo_toml_patch(
            fixture.provider.path(),
            fixture.output.path(),
            None,
            &old_spec,
        )
        .unwrap();

        assert_eq!(patch_name, None);
        assert!(!fixture
            .output
            .path()
            .join("0003-fix-range-dependencies.patch")
            .exists());
    }

    #[test]
    fn second_regen_with_new_dependency_change_appends_patch2() {
        let fixture = RegenFixture::new();
        fixture.write_source_archive(BASE_CARGO);
        fixture.write_patch("old-fix.patch", BASE_CARGO, PATCH0_CARGO);
        fixture.write_patch(
            "0002-fix-range-dependencies.patch",
            PATCH0_CARGO,
            PATCH0_PLUS_BAR_CARGO,
        );
        fixture.write_provider_cargo_toml(PATCH0_PLUS_BAR_BAZ_CARGO);
        fixture.write_output_payload(&["old-fix.patch", "0002-fix-range-dependencies.patch"]);
        let old_spec = fixture.spec(&[
            "Patch0:         old-fix.patch",
            "Patch1:         0002-fix-range-dependencies.patch",
        ]);

        let patch_name = maybe_write_cargo_toml_patch(
            fixture.provider.path(),
            fixture.output.path(),
            None,
            &old_spec,
        )
        .unwrap()
        .unwrap();

        assert_eq!(patch_name, "0003-fix-range-dependencies.patch");
        assert!(fixture
            .output
            .path()
            .join("0002-fix-range-dependencies.patch")
            .exists());
        let patch = fs::read_to_string(fixture.output.path().join(&patch_name)).unwrap();
        assert!(patch.contains("+version = \"0.0.6\""));
        assert!(!patch.contains("+version = \"0.8.9\""));

        let merged = merge_spec_source_metadata(&fixture.new_spec(), &old_spec, Some(&patch_name));
        assert!(merged.contains("Patch0:         old-fix.patch"));
        assert!(merged.contains("Patch1:         0002-fix-range-dependencies.patch"));
        assert!(merged.contains("Patch2:         0003-fix-range-dependencies.patch"));
    }

    fn line_index(text: &str, prefix: &str) -> Option<usize> {
        text.lines()
            .position(|line| line.trim_start().starts_with(prefix))
    }

    struct RegenFixture {
        provider: tempfile::TempDir,
        output: tempfile::TempDir,
    }

    impl RegenFixture {
        fn new() -> Self {
            Self {
                provider: tempfile::tempdir().unwrap(),
                output: tempfile::tempdir().unwrap(),
            }
        }

        fn write_source_archive(&self, cargo_toml: &str) {
            let archive = fs::File::create(self.provider.path().join("source.tar.gz")).unwrap();
            let encoder = GzEncoder::new(archive, Compression::default());
            let mut builder = Builder::new(encoder);
            let mut header = Header::new_gnu();
            header.set_size(cargo_toml.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "crate-1.0.0/Cargo.toml", cargo_toml.as_bytes())
                .unwrap();
            let encoder = builder.into_inner().unwrap();
            encoder.finish().unwrap();
        }

        fn write_patch(&self, name: &str, before: &str, after: &str) {
            let patch = unified_cargo_toml_diff(before.as_bytes(), after.as_bytes()).unwrap();
            fs::write(self.provider.path().join(name), patch).unwrap();
        }

        fn write_provider_cargo_toml(&self, cargo_toml: &str) {
            fs::write(self.provider.path().join("Cargo.toml"), cargo_toml).unwrap();
        }

        fn write_output_payload(&self, patch_names: &[&str]) {
            for patch_name in patch_names {
                fs::copy(
                    self.provider.path().join(patch_name),
                    self.output.path().join(patch_name),
                )
                .unwrap();
            }
        }

        fn spec(&self, patch_lines: &[&str]) -> String {
            format!(
                "%global crate_name fixture\nSource0:        source.tar.gz\n{}\nBuildArch:      noarch\nBuildSystem:    rustcrates\n\nBuildRequires:  rust-rpm-macros\n",
                patch_lines.join("\n")
            )
        }

        fn new_spec(&self) -> String {
            "%global crate_name fixture\nSource:         generated.tar.gz\nBuildArch:      noarch\nBuildSystem:    rustcrates\n\nBuildRequires:  rust-rpm-macros\n".to_string()
        }
    }

    const BASE_CARGO: &str = r#"[package]
name = "fixture"
version = "1.0.0"

[dependencies.foo]
version = "1.0.0"

[dependencies.bar]
version = "0.7.0"

[dependencies.baz]
version = "0.0.5"
"#;

    const PATCH0_CARGO: &str = r#"[package]
name = "fixture"
version = "1.0.0"

[dependencies.foo]
version = "1.2.3"

[dependencies.bar]
version = "0.7.0"

[dependencies.baz]
version = "0.0.5"
"#;

    const PATCH0_PLUS_BAR_CARGO: &str = r#"[package]
name = "fixture"
version = "1.0.0"

[dependencies.foo]
version = "1.2.3"

[dependencies.bar]
version = "0.8.9"

[dependencies.baz]
version = "0.0.5"
"#;

    const PATCH0_PLUS_BAR_BAZ_CARGO: &str = r#"[package]
name = "fixture"
version = "1.0.0"

[dependencies.foo]
version = "1.2.3"

[dependencies.bar]
version = "0.8.9"

[dependencies.baz]
version = "0.0.6"
"#;
}
