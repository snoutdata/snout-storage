//! The `storage` schema in a project's database, and the tenants table in the metadata database.
//!
//! Our own migrations, under `migrations/`, run in order, each in its own transaction together
//! with its ledger row. The ledger (`migrations`, in the schema the migrations are for) records
//! each file's SHA-256, so a file edited after it ran is an error that names it, never a quiet
//! divergence between databases. `.gitattributes` keeps a checkout from rewriting the bytes.
//!
//! The whole run holds an advisory lock, so two servers starting at once never migrate one
//! database twice.

use sha2::{Digest, Sha256};
use tokio_postgres::Client;

pub struct Migration {
	pub id: i32,
	pub name: &'static str,
	pub sql: &'static str,
}

impl Migration {
	pub fn hash(&self) -> String {
		hex::encode(Sha256::digest(self.sql.as_bytes()))
	}
}

/// Which database a set of migrations is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
	/// A project's database: the `storage` schema, made here only when it is missing.
	Tenant,
	/// The metadata database: its `public` schema.
	Metadata,
}

impl Target {
	fn schema(self) -> &'static str {
		match self {
			Target::Tenant => "storage",
			Target::Metadata => "public",
		}
	}
}

/// "snout-st", so it collides with no other advisory lock by accident.
const LOCK_KEY: i64 = 0x736e_6f75_742d_7374;

/// The search path every connection to a project's database uses.
pub const SEARCH_PATH: &str = "storage, public, extensions";

#[derive(Debug, Clone)]
pub struct Roles {
	pub install_roles: bool,
	pub anon: String,
	pub authenticated: String,
	pub service: String,
	pub super_user: String,
}

impl Default for Roles {
	fn default() -> Self {
		Self {
			install_roles: false,
			anon: "anon".into(),
			authenticated: "authenticated".into(),
			service: "service_role".into(),
			super_user: "postgres".into(),
		}
	}
}

#[derive(Debug, thiserror::Error)]
pub enum MigrationError {
	/// The server's own sentence when there is one: `tokio_postgres::Error` displays a bare
	/// "db error".
	#[error("database: {}", .0.as_db_error().map_or_else(|| .0.to_string(), |e| e.message().to_string()))]
	Database(#[from] tokio_postgres::Error),
	#[error(
		"migration {id} was applied as '{applied_name}' with hash {applied}, and this server's migration {id} is '{name}' with hash {expected}: the schema was made by something else, or a migration file changed after it ran"
	)]
	Mismatch {
		id: i32,
		name: String,
		applied_name: String,
		applied: String,
		expected: String,
	},
	#[error("migration {id} ({name}) failed and was rolled back; nothing after it ran: {reason}")]
	Failed {
		id: i32,
		name: String,
		reason: String,
	},
}

fn literal(value: &str) -> String {
	format!("'{}'", value.replace('\'', "''"))
}

/// Runs whatever of `migrations` this database has not run, and returns the ids it ran.
pub async fn migrate(
	client: &mut Client,
	migrations: &[Migration],
	target: Target,
	roles: &Roles,
) -> Result<Vec<i32>, MigrationError> {
	client
		.batch_execute(&format!("SET search_path TO {SEARCH_PATH}"))
		.await?;
	loop {
		let row = client
			.query_one("SELECT pg_try_advisory_lock($1)", &[&LOCK_KEY])
			.await?;
		if row.get::<_, bool>(0) {
			break;
		}
		tokio::time::sleep(std::time::Duration::from_secs(1)).await;
	}
	let outcome = run_locked(client, migrations, target, roles).await;
	// Released whatever happened; a failed unlock on a dying connection releases with it.
	let _ = client
		.execute("SELECT pg_advisory_unlock($1)", &[&LOCK_KEY])
		.await;
	outcome
}

async fn run_locked(
	client: &mut Client,
	migrations: &[Migration],
	target: Target,
	roles: &Roles,
) -> Result<Vec<i32>, MigrationError> {
	let schema = target.schema();
	if target == Target::Tenant {
		// Looked up first: `CREATE SCHEMA IF NOT EXISTS` checks CREATE on the database before it
		// checks existence, and a database prepared for this server makes the schema in advance,
		// owned by the role that connects, so that role needs no database-wide privilege.
		let exists: bool = client
			.query_one(
				"SELECT EXISTS (SELECT FROM pg_namespace WHERE nspname = 'storage')",
				&[],
			)
			.await?
			.get(0);
		if !exists {
			client.batch_execute("CREATE SCHEMA storage").await?;
		}
	}
	client
		.batch_execute(&format!(
			"CREATE TABLE IF NOT EXISTS {schema}.migrations (\
			 id integer PRIMARY KEY, name text NOT NULL, hash text NOT NULL, \
			 executed_at timestamptz NOT NULL DEFAULT now())"
		))
		.await?;

	let mut applied: Vec<(i32, String, String)> = Vec::new();
	for row in client
		.query(
			&format!("SELECT id, name, hash FROM {schema}.migrations ORDER BY id"),
			&[],
		)
		.await?
	{
		applied.push((row.get(0), row.get(1), row.get(2)));
	}
	for migration in migrations {
		if let Some((id, name, hash)) = applied.iter().find(|(id, _, _)| *id == migration.id) {
			let expected = migration.hash();
			if *hash != expected || name != migration.name {
				return Err(MigrationError::Mismatch {
					id: *id,
					name: migration.name.to_string(),
					applied_name: name.clone(),
					applied: hash.clone(),
					expected,
				});
			}
		}
	}

	let pending: Vec<&Migration> = migrations
		.iter()
		.filter(|m| !applied.iter().any(|(id, _, _)| *id == m.id))
		.collect();
	if pending.is_empty() {
		return Ok(Vec::new());
	}
	// What the migrations read to name roles (session-wide, for this connection only).
	client
		.batch_execute(&format!(
			"SELECT set_config('storage.install_roles', {}, false), set_config('storage.anon_role', {}, false), \
			 set_config('storage.authenticated_role', {}, false), set_config('storage.service_role', {}, false), \
			 set_config('storage.super_user', {}, false)",
			literal(if roles.install_roles { "true" } else { "false" }),
			literal(&roles.anon),
			literal(&roles.authenticated),
			literal(&roles.service),
			literal(&roles.super_user),
		))
		.await?;

	let mut ran = Vec::new();
	for migration in pending {
		let result: Result<(), tokio_postgres::Error> = async {
			client.batch_execute("START TRANSACTION").await?;
			client.batch_execute(migration.sql).await?;
			client
				.execute(
					&format!(
						"INSERT INTO {schema}.migrations (id, name, hash) VALUES ($1, $2, $3)"
					),
					&[&migration.id, &migration.name, &migration.hash()],
				)
				.await?;
			client.batch_execute("COMMIT").await?;
			Ok(())
		}
		.await;
		if let Err(error) = result {
			let _ = client.batch_execute("ROLLBACK").await;
			let reason = error
				.as_db_error()
				.map_or_else(|| error.to_string(), |e| e.message().to_string());
			return Err(MigrationError::Failed {
				id: migration.id,
				name: migration.name.to_string(),
				reason,
			});
		}
		ran.push(migration.id);
	}
	Ok(ran)
}

#[cfg(test)]
mod tests {
	use crate::migration_files::{METADATA, TENANT};

	#[test]
	fn each_list_is_ordered_and_unique() {
		for list in [TENANT, METADATA] {
			assert!(!list.is_empty());
			assert!(list.windows(2).all(|w| w[0].id < w[1].id));
		}
	}

	#[test]
	fn migration_files_keep_lf_endings() {
		// The ledger hashes the bytes: a CRLF checkout would make every database look changed.
		assert!(
			TENANT.iter().chain(METADATA).all(|m| !m.sql.contains('\r')),
			"a migration file has CRLF endings"
		);
	}
}
