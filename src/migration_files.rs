//! The migrations, in the order they run. A migration's statements are never edited once
//! released: a change is a new file with the next id, because the ledger in every database holds
//! each file's hash. A file whose words change and statements do not (the own layout's names,
//! 2026-10-14) keeps its earlier hashes in `released_as`.

use crate::migrations::Migration;

/// A project's database: the `storage` schema.
pub const TENANT: &[Migration] = &[Migration {
	id: 1,
	name: "storage",
	sql: include_str!("../migrations/tenant/0001-storage.sql"),
	// 0.1.0-0.2.4, written in the old layout's names.
	released_as: &["1f8f5dfe5eaa9f6abc7363664ab28f9151d32a459732e828afbd7ec21c2ac14f"],
}];

/// The metadata database: the tenants this server serves.
pub const METADATA: &[Migration] = &[Migration {
	id: 1,
	name: "tenants",
	sql: include_str!("../migrations/metadata/0001-tenants.sql"),
	released_as: &[],
}];
