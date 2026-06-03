/*
 * Build script for nfsview.
 *
 * Default behaviour: do nothing (the project builds with stable Rust and
 * needs no codegen). When the `ebpf` feature is enabled, compile the BPF
 * C sources in src/bpf/ via libbpf-cargo and emit a Rust skeleton into
 * OUT_DIR/nfs_lat.skel.rs that the runtime loader includes.
 */

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    #[cfg(feature = "ebpf")]
    ebpf::build();
}

#[cfg(feature = "ebpf")]
mod ebpf {
    use libbpf_cargo::SkeletonBuilder;
    use std::env;
    use std::path::PathBuf;

    pub fn build() {
        let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
        let out: PathBuf = PathBuf::from(out_dir).join("nfs_lat.skel.rs");
        let src = "src/bpf/nfs_lat.bpf.c";

        SkeletonBuilder::new()
            .source(src)
            .clang_args(["-I", "src/bpf"])
            .build_and_generate(&out)
            .expect("BPF skeleton build failed");

        println!("cargo:rerun-if-changed=src/bpf");
    }
}
