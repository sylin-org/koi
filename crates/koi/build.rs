fn main() {
    #[cfg(windows)]
    {
        let version = env!("CARGO_PKG_VERSION");
        let mut resource = winresource::WindowsResource::new();
        resource.set("ProductName", "Koi");
        resource.set("ProductVersion", version);
        resource.set("FileVersion", version);
        resource.set("FileDescription", env!("CARGO_PKG_DESCRIPTION"));
        resource.set("CompanyName", "Sylin.org");
        resource.set("OriginalFilename", "koi.exe");
        resource.set("LegalCopyright", "Copyright (c) Sylin.org contributors");
        resource.compile().expect("compile Koi Windows resources");
    }
}
