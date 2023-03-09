use std::env;
use std::fs;
use std::io;
use std::path;

extern crate env_logger;
extern crate log;

extern crate prost_build;
extern crate reqwest;
extern crate zip;

const VERSION: &str = "22.0";

fn get_protoc_url() -> String {
    if cfg!(all(windows, target_pointer_width = "32")) {
        format!("https://github.com/protocolbuffers/protobuf/releases/download/v{0}/protoc-{0}-win32.zip", VERSION)
    } else if cfg!(all(windows, target_pointer_width = "64")) {
        format!("https://github.com/protocolbuffers/protobuf/releases/download/v{0}/protoc-{0}-win64.zip", VERSION)
    } else if cfg!(target_os = "macos") {
        format!("https://github.com/protocolbuffers/protobuf/releases/download/v{0}/protoc-{0}-osx-universal_binary.zip", VERSION)
    } else if cfg!(target_pointer_width = "32") {
        format!("https://github.com/protocolbuffers/protobuf/releases/download/v{0}/protoc-{0}-linux-x86_32.zip", VERSION)
    } else {
        format!("https://github.com/protocolbuffers/protobuf/releases/download/v{0}/protoc-{0}-linux-x86_64.zip", VERSION)
    }
}

fn get_protoc_path() -> &'static str {
    if cfg!(windows) {
        "protoc.exe"
    } else {
        "protoc"
    }
}

fn map_reqwest_error(e: reqwest::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, e)
}

fn download_protoc() -> io::Result<()> {
    let tmpdir = env::var("CARGO_TARGET_TMPDIR").unwrap_or_default();
    let prebuilt_dir = if tmpdir.is_empty(){ env::current_dir()? } else {
      path::PathBuf::from(tmpdir)
    };
    let protoc_download_dir = prebuilt_dir.join("prebuilt");
    if !protoc_download_dir.exists() {
        let _ = fs::create_dir_all(&protoc_download_dir)?;
    }

    let protoc_bin = protoc_download_dir.join("bin").join(get_protoc_path());
    if protoc_bin.exists() {
        log::info!(
            "{0} already existed, skip downloading.",
            protoc_bin.display()
        );
        println!(
            "{0} already existed, skip downloading.",
            protoc_bin.display()
        );

        let protoc_bin_normalize = protoc_bin
            .into_os_string()
            .into_string()
            .unwrap()
            .replace("\\", "/");
        env::set_var("PROTOC", &protoc_bin_normalize);
        log::info!("export PROTOC={}", protoc_bin_normalize);
        println!("export PROTOC={}", protoc_bin_normalize);
        return Ok(());
    }
    log::info!("{0} not found, start downloading.", protoc_bin.display());
    println!("{0} not found, start downloading.", protoc_bin.display());

    let client = reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::limited(128))
        .build()
        .map_err(map_reqwest_error)?;

    let url = get_protoc_url();
    let body = client
        .get(&url)
        .send()
        .map_err(map_reqwest_error)?
        .bytes()
        .map_err(map_reqwest_error)?;
    let download_file_name = path::PathBuf::from(path::Path::new(&url).file_name().unwrap());
    let download_file_path = protoc_download_dir.join(download_file_name);

    {
        let mut file = fs::File::create(&download_file_path)?;
        let mut cursor = io::Cursor::new(body);
        let _ = io::copy(&mut cursor, &mut file)?;
    }

    {
        let archive_file = fs::File::open(download_file_path)?;
        let mut archive = zip::ZipArchive::new(archive_file).map_err(|e| io::Error::from(e))?;

        let _ = archive.extract(&protoc_download_dir).map_err(|e| io::Error::from(e))?;
    }

    let protoc_bin_normalize = protoc_bin
        .into_os_string()
        .into_string()
        .unwrap()
        .replace("\\", "/");
    env::set_var("PROTOC", &protoc_bin_normalize);
    log::info!("export PROTOC={}", protoc_bin_normalize);
    println!("export PROTOC={}", protoc_bin_normalize);

    Ok(())
}

fn init() {
  env_logger::init();

  if env::var("PROTOC").unwrap_or_default().is_empty() {
      if let Err(e) = download_protoc() {
          log::error!("{:?}", e);
          println!("{:?}", e);
          return;
      }
  }
}

pub fn codegen() -> (prost_build::Config, String) {
    init();

    let codegen = prost_build::Config::new();
    let tmpdir = env::var("CARGO_TARGET_TMPDIR").unwrap_or_default();
    let prebuilt_dir = if tmpdir.is_empty(){ env::current_dir().unwrap() } else {
      path::PathBuf::from(tmpdir)
    };
    let protoc_download_dir = prebuilt_dir.join("prebuilt");
    let protobuf_include_dir = protoc_download_dir
        .join("include")
        .into_os_string()
        .into_string()
        .unwrap();

    (codegen, protobuf_include_dir)
}

