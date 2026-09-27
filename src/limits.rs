//! What a bucket name, an object key, a size limit and a MIME type may be.
//!
//! Size and type limits, rule for rule as clients expect them, except
//! where a rule was a defect; each such place says so.

use std::sync::LazyLock;

use regex::Regex;

use crate::error::StorageError;

/// `\w` in a JavaScript regex is ASCII `[A-Za-z0-9_]`, so it is spelled out.
static BUCKET_NAME: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(r"^([A-Za-z0-9_]|!|-|\.|\*|'|\(|\)| |&|\$|@|=|;|:|\+|,|\?)*$")
		.unwrap_or_else(|_| unreachable!("constant regex"))
});
static MIME: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(r"^([a-zA-Z0-9\-+.]+)/([a-zA-Z0-9\-+.]+)(;\s*charset=[a-zA-Z0-9\-]+)?$|\*$")
		.unwrap_or_else(|_| unreachable!("constant regex"))
});
static SIZE: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(r"(?i)(^[0-9]+(?:\.[0-9]+)?)(gb|mb|kb|b)$")
		.unwrap_or_else(|_| unreachable!("constant regex"))
});

/// Reserved bucket-name suffixes.
const RESERVED_SUFFIXES: [&str; 1] = ["--table-s3"];

pub fn is_valid_bucket_name(name: &str) -> bool {
	let length = name.chars().count();
	length > 0 && length < 101 && BUCKET_NAME.is_match(name)
}

/// `mustBeValidBucketName` + `mustBeNotReservedBucketName` + the whitespace rule of `createBucket`.
pub fn must_be_valid_new_bucket_name(name: &str) -> Result<(), StorageError> {
	if name.trim().len() != name.len()
		|| !is_valid_bucket_name(name)
		|| RESERVED_SUFFIXES.iter().any(|s| name.ends_with(s))
	{
		return Err(StorageError::invalid_bucket_name());
	}
	Ok(())
}

pub fn must_be_valid_bucket_name(name: &str) -> Result<(), StorageError> {
	if is_valid_bucket_name(name) {
		Ok(())
	} else {
		Err(StorageError::invalid_bucket_name())
	}
}

/// An object key. **Deliberately wider than the original rule**, which allows only an ASCII subset
/// (`\w` and a list of punctuation), so `望舌诊病.pdf` is refused; S3 takes any UTF-8, and so do
/// we, except control characters, which no file name needs and a header cannot carry.
pub fn is_valid_key(key: &str) -> bool {
	!key.is_empty() && !key.chars().any(char::is_control)
}

pub fn must_be_valid_key(key: &str) -> Result<(), StorageError> {
	if is_valid_key(key) {
		Ok(())
	} else {
		Err(StorageError::invalid_key(key))
	}
}

/// `parseFileSizeToBytes`. Units are decimal (1 MB = 1,000,000 bytes), as clients expect.
/// **Deliberately exact:** the original rule rounds the number to three significant
/// figures first (`'1024MB'` became 1,020,000,000); this is exact.
pub fn parse_file_size(value: &str) -> Result<u64, StorageError> {
	let captures = SIZE
		.captures(value)
		.ok_or_else(StorageError::invalid_file_size_limit)?;
	let (number, unit) = (&captures[1], captures[2].to_ascii_uppercase());
	let multiplier: u64 = match unit.as_str() {
		"GB" => 1_000_000_000,
		"MB" => 1_000_000,
		"KB" => 1_000,
		_ => 1,
	};
	// Exact decimal arithmetic on the digits, so no float can round a limit.
	let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
	let digits = format!("{whole}{fraction}");
	let scale = 10u64
		.checked_pow(fraction.len() as u32)
		.ok_or_else(StorageError::invalid_file_size_limit)?;
	let value: u128 = digits
		.parse()
		.map_err(|_| StorageError::invalid_file_size_limit())?;
	let bytes = value * u128::from(multiplier) / u128::from(scale);
	u64::try_from(bytes).map_err(|_| StorageError::invalid_file_size_limit())
}

/// `validateMimeType` for a bucket's `allowed_mime_types`.
pub fn validate_mime_types(types: &[String]) -> Result<(), StorageError> {
	for mime in types {
		if mime.len() > 1000 || !MIME.is_match(mime) {
			return Err(StorageError::invalid_mime_type(mime));
		}
	}
	Ok(())
}

/// Whether an upload's Content-Type is allowed by a bucket's list (`uploader.validateMimeType`).
/// **Deliberately:** compared without its parameters, so
/// `text/plain;charset=UTF-8` (what the JavaScript client sends by default) matches `text/plain`.
pub fn mime_allowed(content_type: &str, allowed: &[String]) -> bool {
	if allowed.is_empty() {
		return true;
	}
	let essence = content_type
		.split(';')
		.next()
		.unwrap_or("")
		.trim()
		.to_ascii_lowercase();
	let (kind, sub) = essence.split_once('/').unwrap_or((essence.as_str(), ""));
	allowed.iter().any(|entry| {
		let entry = entry
			.split(';')
			.next()
			.unwrap_or("")
			.trim()
			.to_ascii_lowercase();
		let (allowed_kind, allowed_sub) = entry.split_once('/').unwrap_or((entry.as_str(), ""));
		entry == "*" || (allowed_kind == kind && (allowed_sub == "*" || allowed_sub == sub))
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn bucket_names_follow_the_rule() {
		assert!(is_valid_bucket_name("avatars"));
		assert!(is_valid_bucket_name("my bucket (1)"));
		assert!(!is_valid_bucket_name("a/b"));
		assert!(!is_valid_bucket_name(""));
		assert!(!is_valid_bucket_name(&"x".repeat(101)));
		assert!(must_be_valid_new_bucket_name(" padded").is_err());
		assert!(must_be_valid_new_bucket_name("analytics--table-s3").is_err());
	}

	#[test]
	fn sizes_are_exact_decimal() {
		assert_eq!(parse_file_size("1024MB").ok(), Some(1_024_000_000));
		assert_eq!(parse_file_size("1234B").ok(), Some(1234));
		assert_eq!(parse_file_size("1.5gb").ok(), Some(1_500_000_000));
		assert_eq!(parse_file_size("20KB").ok(), Some(20_000));
		assert_eq!(
			parse_file_size("20 MB"),
			Err(StorageError::invalid_file_size_limit())
		);
		assert_eq!(
			parse_file_size("-1MB"),
			Err(StorageError::invalid_file_size_limit())
		);
	}

	#[test]
	fn mime_types_are_validated_and_matched_without_parameters() {
		assert!(
			validate_mime_types(&[
				"image/png".into(),
				"text/plain;charset=utf-8".into(),
				"image/*".into()
			])
			.is_ok()
		);
		assert!(validate_mime_types(&["not a mime".into()]).is_err());
		let allowed = vec!["text/plain".to_string(), "image/*".to_string()];
		assert!(mime_allowed("text/plain;charset=UTF-8", &allowed));
		assert!(mime_allowed("image/webp", &allowed));
		assert!(!mime_allowed("application/pdf", &allowed));
		assert!(mime_allowed("anything/at-all", &[]));
	}

	#[test]
	fn keys_take_any_utf8_but_control_characters() {
		assert!(is_valid_key("望舌诊病.pdf"));
		assert!(is_valid_key("folder/sub folder/it's (1).txt"));
		assert!(!is_valid_key(""));
		assert!(!is_valid_key("bad\nname"));
	}
}
