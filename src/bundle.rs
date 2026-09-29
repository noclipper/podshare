//! The .pod file: a tar of manifest, transcript and files, compressed and then
//! encrypted with a random key that only travels in the share string.

use anyhow::{anyhow, bail, ensure, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde_json::Value;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use crate::scan;

const MAGIC: &[u8; 4] = b"POD1";
const NONCE: usize = 24;
/// Most a pod may unpack to, in total and per file, so a small crafted pod can't exhaust memory.
pub struct Limits {
    pub total: u64,
    pub file: u64,
}

pub struct Pod {
    pub manifest: Value,
    /// The session in the agent's own format, for resuming in that agent.
    pub transcript: Vec<u8>,
    /// The same conversation in the neutral format (docs/format.md), for other agents.
    pub conversation: Vec<u8>,
    /// Paths relative to the project root.
    pub files: Vec<(PathBuf, Vec<u8>)>,
}

/// The encrypted pod and the key that opens it.
pub fn seal(pod: &Pod) -> Result<(Vec<u8>, String)> {
    let mut tar = tar::Builder::new(Vec::new());
    add(&mut tar, Path::new("manifest.json"), &serde_json::to_vec_pretty(&pod.manifest)?)?;
    add(&mut tar, Path::new("transcript.jsonl"), &pod.transcript)?;
    add(&mut tar, Path::new("conversation.jsonl"), &pod.conversation)?;
    for (rel, bytes) in &pod.files {
        add(&mut tar, &Path::new("files").join(rel), bytes)?;
    }
    let plain = zstd::encode_all(&tar.into_inner()?[..], 10)?;
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let sealed = XChaCha20Poly1305::new(&key).encrypt(&nonce, &plain[..]).map_err(|_| anyhow!("encryption failed"))?;
    Ok(([&MAGIC[..], nonce.as_slice(), &sealed[..]].concat(), URL_SAFE_NO_PAD.encode(key)))
}

fn add(tar: &mut tar::Builder<Vec<u8>>, path: &Path, bytes: &[u8]) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    Ok(tar.append_data(&mut header, path, bytes)?)
}

/// Decrypts a pod, refusing anything that could escape the target folder or
/// reconfigure the receiver's agent.
pub fn unseal(data: &[u8], key: &str, limits: Limits) -> Result<Pod> {
    ensure!(data.len() > MAGIC.len() + NONCE && data.starts_with(MAGIC), "not a pod file");
    let key = URL_SAFE_NO_PAD.decode(key).ok().filter(|k| k.len() == 32).context("malformed key")?;
    let (nonce, sealed) = data[MAGIC.len()..].split_at(NONCE);
    let plain = XChaCha20Poly1305::new(Key::from_slice(&key))
        .decrypt(XNonce::from_slice(nonce), sealed)
        .map_err(|_| anyhow!("wrong key, or the pod was damaged or tampered with"))?;
    let mut tar_bytes = Vec::new();
    zstd::Decoder::new(&plain[..])?.take(limits.total + 1).read_to_end(&mut tar_bytes)?;
    ensure!(tar_bytes.len() as u64 <= limits.total, "pod unpacks to more than {} MB; refusing to open", limits.total >> 20);

    let (mut manifest, mut transcript, mut conversation, mut files) = (None, None, None, Vec::new());
    for entry in tar::Archive::new(&tar_bytes[..]).entries()? {
        let mut entry = entry?;
        ensure!(entry.header().entry_type().is_file(), "pod contains a link or special file; refusing to open");
        let path = entry.path()?.into_owned();
        let is_file = path.starts_with("files");
        ensure!(!is_file || entry.size() <= limits.file, "pod contains an oversized file {}; refusing to open", path.display());
        let mut bytes = Vec::new();
        entry.read_to_end(&mut bytes)?;
        match path.to_str() {
            Some("manifest.json") => manifest = Some(serde_json::from_slice(&bytes)?),
            Some("transcript.jsonl") => transcript = Some(bytes),
            Some("conversation.jsonl") => conversation = Some(bytes),
            _ => {
                let rel = path.strip_prefix("files").map_err(|_| anyhow!("unexpected entry {}", path.display()))?;
                ensure!(
                    rel.components().all(|c| matches!(c, Component::Normal(_))),
                    "unsafe path {} in pod; refusing to open",
                    rel.display()
                );
                if let Some(why) = scan::agent_config(rel) {
                    bail!("pod contains {} ({why}); refusing to open", rel.display());
                }
                ensure!(bytes.len() as u64 <= limits.file, "pod contains an oversized file {}; refusing to open", rel.display());
                files.push((rel.to_path_buf(), bytes));
            }
        }
    }
    Ok(Pod {
        manifest: manifest.context("pod has no manifest")?,
        transcript: transcript.context("pod has no transcript")?,
        conversation: conversation.unwrap_or_default(),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SMALL: Limits = Limits { total: 1 << 20, file: 1 << 20 };

    fn pod(files: &[(&str, &str)]) -> Pod {
        Pod {
            manifest: json!({"pod": 1}),
            transcript: b"{}\n".to_vec(),
            conversation: b"{\"role\":\"user\"}\n".to_vec(),
            files: files.iter().map(|(p, b)| (PathBuf::from(p), b.as_bytes().to_vec())).collect(),
        }
    }

    #[test]
    fn round_trips_with_the_right_key_only() {
        let (sealed, key) = seal(&pod(&[("src/a.rs", "fn a() {}")])).unwrap();
        let back = unseal(&sealed, &key, SMALL).unwrap();
        assert_eq!(back.files, vec![(PathBuf::from("src/a.rs"), b"fn a() {}".to_vec())]);
        assert_eq!(back.conversation, b"{\"role\":\"user\"}\n");
        let (_, other) = seal(&pod(&[])).unwrap();
        assert!(unseal(&sealed, &other, SMALL).is_err());
    }

    #[test]
    fn refuses_decompression_bombs() {
        // 3 MB of zeros compresses to a few hundred bytes.
        let mut enc = zstd::Encoder::new(Vec::new(), 3).unwrap();
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..3 {
            std::io::Write::write_all(&mut enc, &chunk).unwrap();
        }
        let plain = enc.finish().unwrap();
        let key = XChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let sealed = XChaCha20Poly1305::new(&key).encrypt(&nonce, &plain[..]).unwrap();
        let pod = [&MAGIC[..], nonce.as_slice(), &sealed[..]].concat();
        let err = unseal(&pod, &URL_SAFE_NO_PAD.encode(key), SMALL).err().unwrap().to_string();
        assert!(err.contains("more than 1 MB"), "{err}");
    }

    #[test]
    fn detects_tampering() {
        let (mut sealed, key) = seal(&pod(&[("a.txt", "x")])).unwrap();
        *sealed.last_mut().unwrap() ^= 1;
        assert!(unseal(&sealed, &key, SMALL).is_err());
    }

    #[test]
    fn refuses_pods_that_would_configure_the_receivers_agent() {
        for bad in [".claude/settings.json", ".mcp.json", ".envrc", ".git/hooks/post-checkout", ".vscode/tasks.json"] {
            let (sealed, key) = seal(&pod(&[(bad, "{}")])).unwrap();
            let err = unseal(&sealed, &key, SMALL).err().expect(bad).to_string();
            assert!(err.contains("refusing"), "{bad}: {err}");
        }
    }
}
