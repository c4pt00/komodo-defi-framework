#![cfg(feature = "run-docker-tests")]
#![feature(async_closure)]
#![feature(custom_test_frameworks)]
#![feature(test)]
#![test_runner(docker_tests_runner)]
#![feature(drain_filter)]
#![feature(hash_raw_entry)]
#![cfg(not(target_arch = "wasm32"))]

#[cfg(test)]
#[macro_use]
extern crate common;
#[cfg(test)]
#[macro_use]
extern crate gstuff;
#[cfg(test)]
#[macro_use]
extern crate lazy_static;
#[cfg(test)]
#[macro_use]
extern crate serde_json;
#[cfg(test)] extern crate ser_error_derive;
#[cfg(test)] extern crate test;

use std::env;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;
use test::{test_main, StaticBenchFn, StaticTestFn, TestDescAndFn};
use testcontainers::clients::Cli;

mod docker_tests;
use docker_tests::docker_tests_common::*;

#[allow(dead_code)] mod integration_tests_common;

// AP: custom test runner is intended to initialize the required environment (e.g. coin daemons in the docker containers)
// and then gracefully clear it by dropping the RAII docker container handlers
// I've tried to use static for such singleton initialization but it turned out that despite
// rustc allows to use Drop as static the drop fn won't ever be called
// NB: https://github.com/rust-lang/rfcs/issues/1111
// the only preparation step required is Zcash params files downloading:
// Windows - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.bat
// Linux and MacOS - https://github.com/KomodoPlatform/komodo/blob/master/zcutil/fetch-params.sh
pub fn docker_tests_runner(tests: &[&TestDescAndFn]) {
    // pretty_env_logger::try_init();
    let docker = Cli::default();
    let mut containers = vec![];

    let skip_docker_tests_runner = std::env::var("SKIP_DOCKER_TESTS_RUNNER")
        .map(|v| v == "1")
        .unwrap_or(false);
    // skip Docker containers initialization if we are intended to run test_mm_start only
    if !skip_docker_tests_runner {
        const IMAGES: &[&str] = &[SIA_DOCKER_IMAGE_WITH_TAG];

        for image in IMAGES {
            pull_docker_image(image);
            remove_docker_containers(image);
        }

        let _runtime_dir = prepare_runtime_dir().unwrap();

        let sia_node = sia_docker_node(&docker, "SIA", 9980);
        println!("ran container?");
        containers.push(sia_node);
    }
    // detect if docker is installed
    // skip the tests that use docker if not installed
    let owned_tests: Vec<_> = tests
        .iter()
        .map(|t| match t.testfn {
            StaticTestFn(f) => TestDescAndFn {
                testfn: StaticTestFn(f),
                desc: t.desc.clone(),
            },
            StaticBenchFn(f) => TestDescAndFn {
                testfn: StaticBenchFn(f),
                desc: t.desc.clone(),
            },
            _ => panic!("non-static tests passed to lp_coins test runner"),
        })
        .collect();
    let args: Vec<String> = env::args().collect();
    test_main(&args, owned_tests, None);
}

fn pull_docker_image(name: &str) {
    Command::new("docker")
        .arg("pull")
        .arg(name)
        .status()
        .expect("Failed to execute docker command");
}

fn remove_docker_containers(name: &str) {
    let stdout = Command::new("docker")
        .arg("ps")
        .arg("-f")
        .arg(format!("ancestor={}", name))
        .arg("-q")
        .output()
        .expect("Failed to execute docker command");

    let reader = BufReader::new(stdout.stdout.as_slice());
    let ids: Vec<_> = reader.lines().map(|line| line.unwrap()).collect();
    if !ids.is_empty() {
        Command::new("docker")
            .arg("rm")
            .arg("-f")
            .args(ids)
            .status()
            .expect("Failed to execute docker command");
    }
}
fn prepare_runtime_dir() -> std::io::Result<PathBuf> {
    let project_root = {
        let mut current_dir = std::env::current_dir().unwrap();
        current_dir.pop();
        current_dir.pop();
        current_dir
    };

    let containers_state_dir = project_root.join(".docker/container-state");
    assert!(containers_state_dir.exists());
    let containers_runtime_dir = project_root.join(".docker/container-runtime");

    // Remove runtime directory if it exists to copy containers files to a clean directory
    if containers_runtime_dir.exists() {
        std::fs::remove_dir_all(&containers_runtime_dir).unwrap();
    }

    // Copy container files to runtime directory
    mm2_io::fs::copy_dir_all(&containers_state_dir, &containers_runtime_dir).unwrap();

    Ok(containers_runtime_dir)
}
