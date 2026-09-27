//! The tenant rows' at-rest encryption (CryptoJS's AES format, so existing rows decrypt).
//!
//! The metadata database keeps each tenant's JWT secret, keys and database URL in its metadata database
//! encrypted with `AUTH_ENCRYPTION_KEY` the way CryptoJS's `AES.encrypt(text, passphrase)` does:
//! OpenSSL's `Salted__` format, the key and IV derived from the passphrase and an 8-byte salt by
//! EVP_BytesToKey with MD5 (three rounds, 48 bytes), then AES-256-CBC with PKCS#7 padding, all
//! base64. MD5 here is a key-derivation function fixed by the stored format, not a choice: rows
//! written in this format must keep decrypting.

use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit, block_padding::Pkcs7};
use base64::{Engine, engine::general_purpose::STANDARD};
use md5::{Digest, Md5};

type Encryptor = cbc::Encryptor<aes::Aes256>;
type Decryptor = cbc::Decryptor<aes::Aes256>;

const MAGIC: &[u8; 8] = b"Salted__";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CryptoError {
	#[error("not base64")]
	Encoding,
	#[error("not in the Salted__ format")]
	Format,
	#[error("the key does not decrypt it")]
	Key,
	#[error("the plaintext is not UTF-8")]
	Utf8,
}

/// EVP_BytesToKey(MD5, 1 iteration) for AES-256-CBC: 32 bytes of key, then 16 of IV.
fn derive(passphrase: &str, salt: &[u8]) -> ([u8; 32], [u8; 16]) {
	let mut out = [0u8; 48];
	let mut previous: Vec<u8> = Vec::new();
	for chunk in out.chunks_mut(16) {
		let mut hasher = Md5::new();
		hasher.update(&previous);
		hasher.update(passphrase.as_bytes());
		hasher.update(salt);
		let digest = hasher.finalize();
		chunk.copy_from_slice(&digest);
		previous = digest.to_vec();
	}
	let mut key = [0u8; 32];
	let mut iv = [0u8; 16];
	key.copy_from_slice(&out[..32]);
	iv.copy_from_slice(&out[32..]);
	(key, iv)
}

pub fn decrypt(passphrase: &str, ciphertext: &str) -> Result<String, CryptoError> {
	let raw = STANDARD
		.decode(ciphertext.trim())
		.map_err(|_| CryptoError::Encoding)?;
	if raw.len() < 16 + 16 || &raw[..8] != MAGIC {
		return Err(CryptoError::Format);
	}
	let (key, iv) = derive(passphrase, &raw[8..16]);
	let plain = Decryptor::new(&key.into(), &iv.into())
		.decrypt_padded_vec_mut::<Pkcs7>(&raw[16..])
		.map_err(|_| CryptoError::Key)?;
	String::from_utf8(plain).map_err(|_| CryptoError::Utf8)
}

/// Encrypts with a caller-supplied salt, so the output is testable; `encrypt` draws one.
pub fn encrypt_with_salt(passphrase: &str, plaintext: &str, salt: [u8; 8]) -> String {
	let (key, iv) = derive(passphrase, &salt);
	let body = Encryptor::new(&key.into(), &iv.into())
		.encrypt_padded_vec_mut::<Pkcs7>(plaintext.as_bytes());
	let mut raw = Vec::with_capacity(16 + body.len());
	raw.extend_from_slice(MAGIC);
	raw.extend_from_slice(&salt);
	raw.extend_from_slice(&body);
	STANDARD.encode(raw)
}

pub fn encrypt(passphrase: &str, plaintext: &str) -> String {
	let random = uuid::Uuid::new_v4();
	let mut salt = [0u8; 8];
	salt.copy_from_slice(&random.as_bytes()[..8]);
	encrypt_with_salt(passphrase, plaintext, salt)
}

#[cfg(test)]
mod tests {
	use super::*;

	// Produced by CryptoJS-compatible encryption in Node (the same derivation) with the salt
	// fixed, so this proves we read and write the same format as that implementation.
	const NODE: &str = "U2FsdGVkX18BAgMEBQYHCKyUCneSz2195gHpvFQY3z4hibtpNq+Ltb8/OGUtLoTsKKi/boTr+TnQC+LBeIMYIzVh3n6Ljq7zhGMrdF+FbR0=";
	const PLAIN: &str = "postgres://storage_admin:p%40ss@project-abc:5432/abc";

	#[test]
	fn decrypts_what_node_encrypted() {
		assert_eq!(
			decrypt("snoutpod-test-encryption-key", NODE).as_deref(),
			Ok(PLAIN)
		);
	}

	#[test]
	fn encrypts_exactly_what_node_would() {
		let salt = [1, 2, 3, 4, 5, 6, 7, 8];
		assert_eq!(
			encrypt_with_salt("snoutpod-test-encryption-key", PLAIN, salt),
			NODE
		);
	}

	#[test]
	fn an_empty_string_round_trips() {
		assert_eq!(
			decrypt("k", "U2FsdGVkX1+hoqOkpaanqOK6w74qoInwdgfUIMNQ1ys=").as_deref(),
			Ok("")
		);
		assert_eq!(decrypt("k", &encrypt("k", "")).as_deref(), Ok(""));
	}

	#[test]
	fn the_wrong_key_is_an_error_not_garbage() {
		assert_eq!(decrypt("not-the-key", NODE), Err(CryptoError::Key));
		assert_eq!(decrypt("k", "not base64!"), Err(CryptoError::Encoding));
		assert_eq!(
			decrypt("k", "aGVsbG8gd29ybGQgaGVsbG8gd29ybGQgaGVsbG8="),
			Err(CryptoError::Format)
		);
	}
}
