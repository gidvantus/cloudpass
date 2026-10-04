//! The desktop application, offered for download from the portal.
//!
//! # Why this is more than a static file
//!
//! A link to a binary is a promise: *this* is the program, and it is the one we built. For a
//! password manager that promise is worth keeping explicitly, so the file is described rather
//! than merely served — its name, its size, and the SHA-256 of its bytes. Somebody who wants to
//! check that what they downloaded is what this server offered can do it without asking us.
//!
//! That is also why the hash is computed here, at startup, instead of being pasted into a
//! text file that drifts the moment somebody rebuilds. A hash that is generated from the bytes
//! being served cannot be stale.
//!
//! # Discovery, not configuration
//!
//! The build scripts drop the artifact into `<web root>/download/`, which is the directory the
//! static file handler already serves. There is no list to maintain: whatever installer is
//! newest is the one offered, and a server whose directory is empty simply reports that it has
//! nothing to offer. An error would be wrong — the API is the product and the portal is one
//! client of it; a portal without a download is a portal, not a broken server.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A build of the desktop client that this server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopBuild {
    /// File name inside the download directory.
    pub file_name: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the file's bytes.
    pub sha256: String,
    /// Where a browser fetches it, relative to the server's own origin.
    pub url: String,
    /// The version this artifact was built as, read out of its file name.
    ///
    /// `None` when the name carries no version — an installer renamed by hand, or one
    /// produced by a build that never had a version to stamp. That is a normal answer
    /// rather than a failure: the file is still described and still downloadable, and a
    /// client that was hoping to compare versions simply learns nothing.
    pub version: Option<String>,
}

/// Reads the version out of an installer's file name.
///
/// `CloudPass_1.2.3_x64-setup.exe` is the shape the build script produces, and the version
/// is the field between the underscores that parses as semantic versioning. The name is
/// split on `_` rather than searched with a pattern, so that a version embedded in some
/// other part of the name — a build host, a date — cannot be mistaken for the artifact's
/// own; a field that does not parse whole is then split on `-`, which is what covers a name
/// like `CloudPass-1.2.3-x64-setup.exe`.
///
/// A name that yields nothing returns `None`. The answer is the *canonical* form of the
/// parsed version, so a client never has to wonder whether `1.2.3` and `v1.2.3` describe
/// the same build.
#[must_use]
pub fn parse_version(file_name: &str) -> Option<String> {
    let stem = file_name
        .rsplit_once('.')
        .map_or(file_name, |(stem, _extension)| stem);

    stem.split('_')
        .filter(|field| !field.is_empty())
        .find_map(|field| {
            semver::Version::parse(field).ok().or_else(|| {
                field
                    .split('-')
                    .filter(|piece| !piece.is_empty())
                    .find_map(|piece| semver::Version::parse(piece).ok())
            })
        })
        .map(|version| version.to_string())
}

/// Extensions that mean "a Windows program", in the order we prefer them.
///
/// An installer first: it registers an uninstaller and a shortcut, which is what a person
/// expects from a downloaded application. The bare executable is the fallback for a build that
/// was made without the bundler.
const INSTALLER_EXTENSIONS: [&str; 2] = ["exe", "msi"];

/// Finds the newest desktop build in `directory`, if there is one.
///
/// Returns `None` for a missing directory, an empty one, one holding only the `.gitkeep` that
/// keeps the directory in version control, or one whose only candidate cannot be read. None of
/// those is an error condition for the server.
#[must_use]
pub fn find_build(directory: &Path) -> Option<DesktopBuild> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(directory)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.is_file()
                && path
                    .extension()
                    .and_then(|extension| extension.to_str())
                    .is_some_and(|extension| {
                        INSTALLER_EXTENSIONS
                            .iter()
                            .any(|known| extension.eq_ignore_ascii_case(known))
                    })
        })
        .filter_map(|path| {
            let modified = path.metadata().ok()?.modified().ok()?;
            Some((modified, path))
        })
        .collect();

    // Newest wins. A directory holding yesterday's installer and today's should offer today's,
    // and the alternative — a configured file name — is a second place to forget to update.
    candidates.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    let (_, path) = candidates.into_iter().next()?;

    let file_name = path.file_name()?.to_str()?.to_owned();
    let size = path.metadata().ok()?.len();

    Some(DesktopBuild {
        url: format!("/download/{file_name}"),
        sha256: hash_file(&path)?,
        version: parse_version(&file_name),
        size,
        file_name,
    })
}

/// Streams a file through SHA-256.
///
/// Chunked rather than read-into-memory: the file is tens of megabytes today, and a server
/// that allocates a whole installer to hash it is a server that will one day be handed a
/// bigger one.
fn hash_file(path: &Path) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];

    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Some(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing into a String cannot fail, and a hash that silently lost a byte would be
        // worse than a panic in a function that runs once at startup.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The directory desktop builds are looked for in.
///
/// `CLOUDPASS_DOWNLOAD_DIR` if it is set, otherwise `download/` inside the portal's own root —
/// which is where the build scripts put the artifact and where the static handler already
/// serves from, so the common case needs no configuration at all.
#[must_use]
pub fn resolve_directory(web_root: Option<&Path>) -> Option<PathBuf> {
    if let Ok(configured) = std::env::var("CLOUDPASS_DOWNLOAD_DIR") {
        return std::fs::canonicalize(configured).ok();
    }
    let candidate = web_root?.join("download");
    std::fs::canonicalize(candidate).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "cloudpass-downloads-{label}-{}",
            cloudpass_core::ids::random_uuid()
        ));
        fs::create_dir_all(&dir).expect("create scratch");
        dir
    }

    #[test]
    fn an_empty_directory_offers_nothing() {
        let dir = scratch("empty");
        assert_eq!(find_build(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_directory_that_does_not_exist_offers_nothing() {
        assert_eq!(find_build(Path::new("definitely/not/here")), None);
    }

    #[test]
    fn the_gitkeep_that_holds_the_directory_is_not_an_installer() {
        let dir = scratch("gitkeep");
        fs::write(dir.join(".gitkeep"), b"").expect("write");
        assert_eq!(find_build(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_installer_is_described_with_its_real_hash() {
        let dir = scratch("installer");
        let file = dir.join("CloudPass_0.1.0_x64-setup.exe");
        fs::write(&file, b"not really an installer").expect("write");

        let build = find_build(&dir).expect("found");
        assert_eq!(build.file_name, "CloudPass_0.1.0_x64-setup.exe");
        assert_eq!(build.url, "/download/CloudPass_0.1.0_x64-setup.exe");
        assert_eq!(build.size, "not really an installer".len() as u64);
        assert_eq!(
            build.sha256, "110499c3d4d34a94a1ea70ae7e7353d32708e043bc0ccee13ec9fbdb7a9d20b1",
            "the hash must describe the bytes actually on disk"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    /// The hash is the whole point of describing the file: a person who downloads the
    /// installer should be able to check it against what the server advertised.
    #[test]
    fn the_hash_changes_when_the_bytes_do() {
        let dir = scratch("hash");
        let file = dir.join("CloudPass_0.1.0_x64-setup.exe");

        fs::write(&file, b"first build").expect("write");
        let first = find_build(&dir).expect("found").sha256;

        fs::write(&file, b"second build").expect("write");
        let second = find_build(&dir).expect("found").sha256;

        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_newest_build_is_the_one_offered() {
        let dir = scratch("newest");
        let old = dir.join("CloudPass_0.0.9_x64-setup.exe");
        let new = dir.join("CloudPass_0.1.0_x64-setup.exe");
        fs::write(&old, b"old").expect("write");
        // Filesystems store modification times with a resolution that can be a whole second,
        // so the two writes are separated explicitly rather than by hoping.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        fs::write(&new, b"new").expect("write");

        let build = find_build(&dir).expect("found");
        assert_eq!(build.file_name, "CloudPass_0.1.0_x64-setup.exe");
        assert_eq!(build.size, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    /// The version is what a desktop client compares itself against, so it has to come out
    /// of the name the build script produces — and out of nothing at all when the name does
    /// not carry one.
    #[test]
    fn the_version_is_read_out_of_the_installer_name() {
        assert_eq!(
            parse_version("CloudPass_1.2.3_x64-setup.exe").as_deref(),
            Some("1.2.3")
        );
        assert_eq!(
            parse_version("CloudPass-2.0.10-x64-setup.msi").as_deref(),
            Some("2.0.10")
        );
        assert_eq!(
            parse_version("cloudpass_0.1.0.exe").as_deref(),
            Some("0.1.0")
        );
        // A build host or a date in the name is not the artifact's version, and a name with
        // no version must say so rather than borrow a number from somewhere else.
        assert_eq!(parse_version("CloudPass_x64-setup.exe"), None);
        assert_eq!(parse_version("CloudPass_2024_11_05-setup.exe"), None);
        assert_eq!(parse_version("setup.exe"), None);
    }

    #[test]
    fn a_described_build_carries_the_version_from_its_name() {
        let dir = scratch("version");
        let file = dir.join("CloudPass_1.2.3_x64-setup.exe");
        fs::write(&file, b"installer").expect("write");

        let build = find_build(&dir).expect("found");
        assert_eq!(build.version.as_deref(), Some("1.2.3"));
        // Everything else about the description is unchanged by the addition.
        assert_eq!(build.file_name, "CloudPass_1.2.3_x64-setup.exe");
        assert_eq!(build.url, "/download/CloudPass_1.2.3_x64-setup.exe");
        assert_eq!(build.size, "installer".len() as u64);
        assert_eq!(build.sha256.len(), 64);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_build_whose_name_has_no_version_is_described_without_one() {
        let dir = scratch("noversion");
        fs::write(dir.join("CloudPass_x64-setup.exe"), b"installer").expect("write");

        let build = find_build(&dir).expect("found");
        assert_eq!(build.version, None);
        assert_eq!(build.file_name, "CloudPass_x64-setup.exe");
        assert_eq!(build.sha256.len(), 64);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_non_installer_is_left_alone() {
        let dir = scratch("other");
        fs::write(dir.join("notes.txt"), b"readme").expect("write");
        fs::write(dir.join("cloudpass_web_bg.wasm"), b"\0asm").expect("write");
        assert_eq!(find_build(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }
}
