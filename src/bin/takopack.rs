use clap::Parser;
use nu_ansi_term::Color::Red;

use takopack::cli::{CargoOpt, Cli, Opt, PyOpt};
use takopack::crates::invalidate_crates_io_cache;
use takopack::errors::Result;
use takopack::package::*;
use takopack::recursive_package::RecursivePackager;
use takopack::repo_check::{BuildReqsOptions, RepoCheckOptions, RepoIndexOptions};
use takopack::spec_from_toml::parse_dependencies_from_toml;

#[test]
fn verify_app() {
    use clap::CommandFactory;
    Cli::command().debug_assert()
}

fn real_main() -> Result<i32> {
    let m = Cli::parse();
    use Opt::*;
    match m.command {
        Cargo(cargo_opt) => {
            match cargo_opt {
                CargoOpt::Update => invalidate_crates_io_cache().map(|_| 0),
                CargoOpt::Package {
                    init,
                    mut extract,
                    finish,
                } => {
                    use std::fs;

                    log::info!("preparing crate info");
                    let mut process = PackageProcess::init(init)?;

                    // Get crate name and version
                    let crate_name = process.crate_info().crate_name();
                    let version = process.crate_info().version();

                    let output_names = takopack::util::rust_crate_output_names(crate_name, version);
                    let final_output = takopack::util::package_final_output_dir(
                        extract.directory.as_deref(),
                        &output_names,
                    )?;
                    extract.directory = Some(final_output.clone());

                    process.extract(extract)?;
                    process.apply_overrides()?;
                    process.prepare_orig_tarball()?;
                    process.prepare_takopack_folder(finish)?;

                    // After prepare_takopack_folder, the spec file is in output_dir/takopack/
                    let output_path = process.output_dir.as_ref().unwrap();
                    log::debug!("output_path: {}", output_path.display());
                    log::debug!("output_dirname: {}", final_output.display());

                    let takopack_dir = output_path.join("takopack");
                    let source_spec = takopack_dir.join(&output_names.spec_file);

                    // Create final output directory and copy the spec plus original Cargo.toml.
                    fs::create_dir_all(&final_output)?;
                    let final_spec = final_output.join(&output_names.spec_file);

                    if source_spec.exists() {
                        fs::copy(&source_spec, &final_spec)?;
                        let final_cargo_toml = takopack::util::copy_original_cargo_toml_to_dir(
                            output_path,
                            &final_output,
                        )?;
                        log::info!("Spec file saved to: {}", final_spec.display());
                        println!("Spec file: {}", final_spec.display());

                        // Now cleanup: remove the extraction directory (which has the same name as final_output)
                        // We need to do this carefully to not delete the final spec file
                        if output_path == &final_output {
                            // They are the same directory, just remove everything except the spec file
                            if takopack_dir.exists() {
                                fs::remove_dir_all(&takopack_dir)?;
                            }
                            // Remove other files
                            for entry in fs::read_dir(output_path)? {
                                let entry = entry?;
                                let path = entry.path();
                                if path != final_spec && path != final_cargo_toml {
                                    if path.is_dir() {
                                        fs::remove_dir_all(&path)?;
                                    } else {
                                        fs::remove_file(&path)?;
                                    }
                                }
                            }
                            log::info!("Cleaned up extraction files, kept spec file");
                        } else {
                            // Different directories, safe to remove the whole output_path
                            fs::remove_dir_all(output_path)?;
                            log::info!("Cleaned up extraction directory");
                        }
                    } else {
                        log::warn!("Spec file not found at: {}", source_spec.display());
                        eprintln!("ERROR: Spec file not found!");
                    };

                    Ok(0)
                }
                CargoOpt::Vendor { args } => {
                    log::info!("starting vendor operation (recursive packaging)");
                    let mut packager = RecursivePackager::new(args.output)?;
                    packager.process_crate_recursive(
                        &args.crate_name,
                        args.version.as_deref(),
                        args.config,
                    )?;
                    packager.print_summary();
                    Ok(0)
                }
                CargoOpt::ParseToml { toml_path, output } => {
                    log::info!("parsing dependencies from Cargo.toml");
                    parse_dependencies_from_toml(&toml_path, output)?;
                    Ok(0)
                }
                CargoOpt::Batch { file, output } => {
                    log::info!("starting batch operation from file: {:?}", file);
                    takopack::batch_package::process_batch_file(&file, output)?;
                    Ok(0)
                }
                CargoOpt::LocalPackage {
                    path,
                    output,
                    finish,
                } => {
                    log::info!("packaging from local directory: {:?}", path);
                    takopack::local_package::process_local_package(&path, output, finish)?;
                    Ok(0)
                }
                CargoOpt::BuildReqs {
                    file,
                    index,
                    kind,
                    include_build,
                    include_dev,
                    json,
                    check,
                } => takopack::repo_check::run_buildreqs(
                    &file,
                    index.as_deref(),
                    BuildReqsOptions {
                        kind,
                        include_build,
                        include_dev,
                        json,
                        check,
                    },
                ),
                CargoOpt::RepoIndex {
                    spec_repo_dir,
                    ruyispec,
                    include_all_specs,
                    output,
                } => {
                    let ruyispec_dir =
                        takopack::config::resolve_ruyispec_dir(spec_repo_dir.as_deref(), ruyispec)?;
                    let package_root = takopack::config::ruyispec_package_root(&ruyispec_dir);
                    takopack::repo_check::write_repo_index_with_options(
                        &package_root,
                        &output,
                        RepoIndexOptions { include_all_specs },
                    )?;
                    Ok(0)
                }
                CargoOpt::RepoCheck {
                    cargo_toml,
                    index,
                    kind,
                    check_transitive,
                    json,
                } => takopack::repo_check::run_repo_check(
                    &cargo_toml,
                    &index,
                    RepoCheckOptions {
                        kind,
                        check_transitive,
                        json,
                    },
                ),
                CargoOpt::RepoPlan {
                    cargo_toml,
                    index,
                    kind,
                    check_transitive,
                    json,
                    include_global_warnings,
                } => takopack::repo_check::run_repo_plan(
                    &cargo_toml,
                    &index,
                    takopack::repo_check::RepoPlanOptions {
                        kind,
                        check_transitive,
                        json,
                        include_global_warnings,
                    },
                ),
                CargoOpt::RepoHealth { index, json } => {
                    takopack::repo_check::run_repo_health(&index, json)
                }
                CargoOpt::AppAudit {
                    ruyispec_dir,
                    ruyispec,
                    index,
                    output,
                } => {
                    let ruyispec_dir =
                        takopack::config::resolve_ruyispec_dir(ruyispec_dir.as_deref(), ruyispec)?;
                    let package_root = takopack::config::ruyispec_package_root(&ruyispec_dir);
                    takopack::repo_check::run_app_audit(
                        &ruyispec_dir,
                        &package_root,
                        &index,
                        &output,
                    )?;
                    Ok(0)
                }
                CargoOpt::Track {
                    crate_name,
                    version,
                    from_file,
                    output,
                    database,
                    action_file,
                } => {
                    log::info!("tracking dependencies");
                    takopack::track_command::execute_track(
                        crate_name,
                        version,
                        from_file,
                        output,
                        database,
                        action_file,
                    )?;
                    Ok(0)
                }
            }
        }
        Opt::Py(py_opt) => match py_opt {
            PyOpt::Package {
                name,
                version,
                output,
            } => {
                log::info!("packaging Python package from PyPI");
                takopack::python_package::process_python_package(
                    &name,
                    version.as_deref(),
                    output,
                )?;
                Ok(0)
            }
        },
    }
}

fn main() {
    env_logger::init();
    match real_main() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("{}", Red.bold().paint(format!("takopack failed: {:?}", e)));
            std::process::exit(1);
        }
    }
}
