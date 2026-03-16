fn main() {
    #[cfg(target_os = "macos")]
    {
        // Compile the vmnet C shim.
        cc::Build::new()
            .file("csrc/vmnet_shim.c")
            .compile("vmnet_shim");

        // Link against vmnet.framework.
        println!("cargo:rustc-link-lib=framework=vmnet");
    }
}
