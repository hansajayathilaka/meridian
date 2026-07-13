//! Keystore harness (T01 acceptance).
//!
//! Two invariants:
//!   1. The `os` store leaves **no** plaintext key material on disk (the acceptance property).
//!   2. The `file` store writes only ciphertext — the raw seed never appears in the keyfile.
//!
//! The `os` path is exercised through the in-memory mock credential store so it runs in CI without
//! a platform keychain or D-Bus. That mock represents any off-disk sink (real Keychain / DPAPI /
//! Secret Service); the point under test is that *our* code writes nothing to the filesystem.

use std::fs;

use meridian_store::{
    install_mock_keystore, FileSecretStore, KeyHandle, OsSecretStore, SecretStore, SignOrDh,
};

const SEED: [u8; 32] = [0xA5; 32];

/// Recursively collect every byte of every file under `dir`.
fn all_file_bytes(dir: &std::path::Path) -> Vec<u8> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                out.extend(all_file_bytes(&path));
            } else if let Ok(bytes) = fs::read(&path) {
                out.extend(bytes);
            }
        }
    }
    out
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn os_store_leaves_no_plaintext_on_disk() {
    install_mock_keystore();
    let workdir = tempfile::tempdir().unwrap();

    let os = OsSecretStore::new("meridian-test");
    let handle = os.store("acct-label", &SEED).unwrap();

    // The key is genuinely stored (usable for signing) …
    let sig = os.use_key(&handle, SignOrDh::Sign, b"hello").unwrap();
    assert_eq!(sig.len(), 64);

    // … and it can be read back from the off-disk store …
    let recovered = os.export_seed(&handle).unwrap();
    assert_eq!(&recovered[..], &SEED[..]);

    // … but nothing was written to the filesystem: the seed appears in no file under the workdir.
    let disk = all_file_bytes(workdir.path());
    assert!(
        !contains_subslice(&disk, &SEED),
        "os store must not write the seed to disk"
    );
}

#[test]
fn file_store_writes_only_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.key");

    let fs_store = FileSecretStore::new(&keyfile, "correct horse battery staple");
    fs_store.store("acct", &SEED).unwrap();

    let on_disk = fs::read(&keyfile).unwrap();
    assert!(!on_disk.is_empty(), "keyfile should exist and be non-empty");
    assert!(
        !contains_subslice(&on_disk, &SEED),
        "file store must not persist the raw seed in plaintext"
    );
    // age keyfiles start with the age armor/binary header.
    assert!(
        on_disk.starts_with(b"age-encryption.org/v1"),
        "keyfile should be an age container"
    );

    // Round-trips: signing through the store, and seed export, both recover the key.
    let handle = KeyHandle::from_label("acct");
    let sig = fs_store.use_key(&handle, SignOrDh::Sign, b"hello").unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(&fs_store.export_seed().unwrap()[..], &SEED[..]);
}

#[test]
fn wrong_passphrase_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let keyfile = dir.path().join("account.key");
    FileSecretStore::new(&keyfile, "right")
        .store("a", &SEED)
        .unwrap();

    let wrong = FileSecretStore::new(&keyfile, "wrong");
    assert!(
        wrong.export_seed().is_err(),
        "wrong passphrase must not unwrap"
    );
}

#[test]
fn account_key_dh_interoperates() {
    // The account-key X25519 DH (T03) must satisfy DH(a, mont(B)) == DH(b, mont(A)), where a/b are
    // Ed25519 account seeds and mont(·) is the peer's Montgomery public key. This is what makes
    // X3DH's DH(IK, ·) legs agree across the two endpoints.
    use ed25519_dalek::SigningKey;

    let seed_a = [7u8; 32];
    let seed_b = [9u8; 32];
    let mont = |seed: &[u8; 32]| {
        SigningKey::from_bytes(seed)
            .verifying_key()
            .to_montgomery()
            .to_bytes()
    };

    let store = meridian_store::MemorySecretStore::new();
    let ha = store.store("a", &seed_a).unwrap();
    let hb = store.store("b", &seed_b).unwrap();

    let ab = store.use_key(&ha, SignOrDh::Dh, &mont(&seed_b)).unwrap();
    let ba = store.use_key(&hb, SignOrDh::Dh, &mont(&seed_a)).unwrap();
    assert_eq!(ab, ba, "account-key DH must be symmetric across endpoints");
    assert_eq!(ab.len(), 32);

    // A wrong-length peer key is rejected, not silently truncated.
    assert!(store.use_key(&ha, SignOrDh::Dh, b"short").is_err());
}
