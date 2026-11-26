//! Library usage example: signs a synthetic `SUIT_Envelope` in memory through the public
//! `brody` API, mirroring the "Library usage" section of the README.
//!
//! Run with: `cargo run --example sign_envelope`

use brody::{Algorithm, Signer};
use ciborium::value::Value;

// Throwaway P-256 key (PKCS8 PEM) for demonstration only. Never use it to sign real manifests.
const ES256_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgmszCRujRlOLiEywZ
h5wBh+Hzz3S/N9v/isf0zgmnbh2hRANCAAQ00s4XENy+WZ5ISICdRcSuwCaQ1WUA
WXSFBkWRMYSvj7UfvonsDFML67YB2F6MR5LrF+FGHh7yFSCekjzRCwQ5
-----END PRIVATE KEY-----";

/// Builds a minimal `SUIT_Envelope`: key 2 = bstr wrapping `[digest bstr]`, key 3 = manifest bstr.
fn build_envelope(digest: &[u8], manifest: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let auth_array = Value::Array(vec![Value::Bytes(digest.to_vec())]);
    let mut auth_array_bytes = Vec::new();
    ciborium::ser::into_writer(&auth_array, &mut auth_array_bytes)?;

    let envelope = Value::Map(vec![
        (Value::from(2i64), Value::Bytes(auth_array_bytes)),
        (Value::from(3i64), Value::Bytes(manifest.to_vec())),
    ]);
    let mut envelope_bytes = Vec::new();
    ciborium::ser::into_writer(&envelope, &mut envelope_bytes)?;
    Ok(envelope_bytes)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let envelope_bytes = build_envelope(b"example-suit-digest-bstr", b"example-manifest-bytes")?;

    let signer = Signer::from_pem(ES256_PKCS8_PEM, Algorithm::Es256)?;
    let signed_envelope = brody::sign_envelope(&envelope_bytes, &signer)?;

    let auth_array_bytes = brody::envelope::extract_authentication(&signed_envelope)?;
    let auth_array: Value = ciborium::de::from_reader(auth_array_bytes.as_slice())?;
    let entry_count = match auth_array {
        Value::Array(entries) => entries.len(),
        other => return Err(format!("expected authentication array, got {other:?}").into()),
    };

    println!("Input envelope:  {} bytes", envelope_bytes.len());
    println!("Signed envelope: {} bytes", signed_envelope.len());
    println!("Authentication entries: {entry_count} (original digest + appended COSE_Sign1)");

    Ok(())
}
