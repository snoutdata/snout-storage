//! The migrations, in the order they run. A migration is never edited once released: a change is
//! a new file with the next id, because the ledger in every database holds each file's hash.

use crate::migrations::Migration;

/// A project's database: the `storage` schema.
pub const TENANT: &[Migration] = &[Migration {
	id: 1,
	name: "storage",
	sql: include_str!("../migrations/tenant/0001-storage.sql"),
}];

/// The metadata database: the tenants this server serves.
pub const METADATA: &[Migration] = &[Migration {
	id: 1,
	name: "tenants",
	sql: include_str!("../migrations/metadata/0001-tenants.sql"),
}];
