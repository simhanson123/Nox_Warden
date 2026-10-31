use crate::{Failure, Result};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
};
pub(crate) fn private_file(path: &Path, allow_public_read: bool) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Failure::Invalid)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mask = if allow_public_read { 0o022 } else { 0o077 };
        if metadata.nlink() != 1 || metadata.mode() & mask != 0 {
            return Err(Failure::Invalid);
        }
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let meta = fs::symlink_metadata(parent).map_err(|_| Failure::Invalid)?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err(Failure::Invalid);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o022 != 0 {
            return Err(Failure::Invalid);
        }
    }
    Ok(())
}
pub fn read_private(path: &Path, max: usize) -> Result<Vec<u8>> {
    private_file(path, false)?;
    bounded_read(path, max)
}
fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|_| Failure::Invalid)?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Invalid)?;
    if bytes.len() > max {
        return Err(Failure::Invalid);
    }
    Ok(bytes)
}
pub(crate) fn load_ui(root: &Path) -> Result<BTreeMap<String, (String, Vec<u8>)>> {
    let mut assets = BTreeMap::new();
    let mut files = vec![root.join("index.html")];
    let assets_dir = root.join("assets");
    if assets_dir.exists() {
        for item in fs::read_dir(&assets_dir).map_err(|_| Failure::Invalid)? {
            files.push(item.map_err(|_| Failure::Invalid)?.path());
            if files.len() > 64 {
                return Err(Failure::Invalid);
            }
        }
    }
    let mut total = 0usize;
    for path in files {
        private_file(&path, true)?;
        let extension = path
            .extension()
            .and_then(|s| s.to_str())
            .ok_or(Failure::Invalid)?;
        let kind = match extension {
            "html" => "text/html; charset=utf-8",
            "js" => "text/javascript; charset=utf-8",
            "css" => "text/css; charset=utf-8",
            "svg" => "image/svg+xml",
            _ => return Err(Failure::Invalid),
        };
        let bytes = bounded_read(&path, 4 * 1024 * 1024)?;
        total += bytes.len();
        if total > 8 * 1024 * 1024 {
            return Err(Failure::Invalid);
        }
        let relative: PathBuf = path
            .strip_prefix(root)
            .map_err(|_| Failure::Invalid)?
            .into();
        let key = format!(
            "/{}",
            relative
                .to_str()
                .ok_or(Failure::Invalid)?
                .replace('\\', "/")
        );
        assets.insert(key, (kind.into(), bytes));
    }
    Ok(assets)
}
