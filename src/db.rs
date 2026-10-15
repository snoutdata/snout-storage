//! The customer's own database, AS THE CALLER. The security core of this server.
//!
//! Every object and bucket operation runs in a transaction that first becomes the caller:
//! `set_config('role', …)` switches to the JWT's Postgres role (`anon`, `authenticated`,
//! `service_role`), and the JWT's claims land in `request.jwt.claims` (and the settings beside it)
//! where the customer's row-level security policies read them through `auth.uid()` and friends.
//! **This server never decides who may see or change a row; the database does.** What a policy
//! refuses comes back as SQLSTATE 42501 and is answered 403, in upstream's words.
//!
//! The preamble sets what policies read (the role, the claims, the request), setting for setting, in one
//! statement, local to the transaction (the third argument `true`), so nothing survives into the
//! next request on the same connection.
//!
//! One pool per tenant, connected with the tenant's own `database_url` (as
//! the storage admin role, to that project's database only), so the credential this shared
//! process holds for one tenant opens that tenant's database and nothing else on the host.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use serde_json::{Map, Value};
use tokio::sync::RwLock;
use tokio_postgres::NoTls;
use tokio_postgres::types::ToSql;

use crate::error::StorageError;
use crate::layout;
use crate::migrations::SEARCH_PATH;

/// Who is asking, as the verified JWT says.
#[derive(Debug, Clone)]
pub struct Caller {
	pub role: String,
	pub jwt: String,
	pub claims: Map<String, Value>,
}

impl Caller {
	pub fn from_claims(jwt: String, claims: Map<String, Value>) -> Self {
		let role = claims
			.get("role")
			.and_then(Value::as_str)
			.filter(|r| !r.is_empty())
			.unwrap_or("anon")
			.to_string();
		Self { role, jwt, claims }
	}

	pub fn sub(&self) -> Option<&str> {
		self.claims.get("sub").and_then(Value::as_str)
	}
}

/// The request facts exposed to policies beside the claims.
#[derive(Debug, Clone, Default)]
pub struct RequestFacts {
	pub method: String,
	pub path: String,
	pub headers: Map<String, Value>,
	pub operation: String,
}

/// SQLSTATE to a storage error, in the words clients already match on.
pub fn map_pg_error(error: &tokio_postgres::Error) -> StorageError {
	let Some(db) = error.as_db_error() else {
		tracing::error!(%error, "database connection");
		return StorageError::database("database error, code: undefined");
	};
	match db.code().code() {
		"42501" => {
			let message = if db.message().contains("row-level security") {
				"new row violates row-level security policy".to_string()
			} else {
				db.message().to_string()
			};
			StorageError::access_denied(message)
		}
		"23505" => StorageError::resource_already_exists(),
		"23503" => StorageError::new(404, "InvalidRequest", "The related resource does not exist"),
		"55P03" => StorageError::resource_locked(),
		"57014" => StorageError::database_timeout(),
		"25006" => StorageError::new(
			503,
			"DatabaseReadOnly",
			"The database is currently in read-only mode. Please try again later.",
		),
		"42P17" => StorageError::new(
			503,
			"DatabaseInvalidObjectDefinition",
			"The database schema is invalid or incompatible.",
		),
		"22P02" => StorageError::new(400, "InvalidParameter", db.message()),
		// A trigger or policy that names what is not there, else our own statement.
		"42703" | "42P01" => match db.position() {
			Some(tokio_postgres::error::ErrorPosition::Internal { .. }) => StorageError::new(
				503,
				"DatabaseSchemaMismatch",
				format!(
					"There is a database schema mismatch in a trigger or RLS policy: {}",
					db.where_().unwrap_or("undefined")
				),
			),
			_ => StorageError::new(
				503,
				"DatabaseSchemaMismatch",
				"The database schema is out of sync. Please run migrations or contact support.",
			),
		},
		code => StorageError::database(format!("database error, code: {code}")),
	}
}

/// Which names a tenant's database has, asked once when its pool is made (OWN-LAYOUT section 3,
/// item 6): one server serves renamed and unrenamed projects at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantLayout {
	/// The new role names exist (`snout_member` ...), so a claim in either vocabulary is run as
	/// the new one; otherwise as the old.
	pub has_new_roles: bool,
	/// `snout_files` when the database has it, else `storage`.
	pub schema: String,
	/// `snout_ext` when the database has it, else `extensions`.
	pub extensions: String,
}

impl Default for TenantLayout {
	fn default() -> Self {
		Self {
			has_new_roles: false,
			schema: "storage".into(),
			extensions: "extensions".into(),
		}
	}
}

impl TenantLayout {
	/// The new layout (OWN-LAYOUT 2b): the schema is `snout_files`, and with it the tables are
	/// `spaces` and `files`. A database has all of the old names or all of the new.
	pub fn is_new(&self) -> bool {
		self.schema == "snout_files"
	}

	/// A statement written with the old names (`objects`, `buckets`, unqualified on the search
	/// path, or `storage.`), in this database's names. Unchanged in an old-layout database.
	pub fn sql<'a>(&self, text: &'a str) -> Cow<'a, str> {
		layout::sql_in_layout(text, self.is_new(), STATEMENTS)
	}

	/// The connection's search path: `SEARCH_PATH` with the resolved names.
	pub fn search_path(&self) -> String {
		SEARCH_PATH
			.split(',')
			.map(str::trim)
			.map(|name| match name {
				"storage" => self.schema.as_str(),
				"extensions" => self.extensions.as_str(),
				other => other,
			})
			.collect::<Vec<_>>()
			.join(",")
	}
}

/// What a statement of this server is rewritten for: the storage tables by their bare names too,
/// since the search path finds them; never role names, which only ever arrive as parameters.
pub const STATEMENTS: layout::Rewrite<'static> = layout::Rewrite {
	bare: &["storage"],
	roles: false,
};

/// The one statement that resolves a `TenantLayout`. The schema is the signal (a database has
/// all of the old names or all of the new): roles are the cluster's, so a role that exists says
/// nothing about this database unless its schema is the new one too.
const LAYOUT_SQL: &str = "select to_regnamespace('snout_files') is not null and to_regrole('snout_member') is not null, \
	case when to_regnamespace('snout_files') is not null then 'snout_files' else 'storage' end, \
	case when to_regnamespace('snout_ext') is not null then 'snout_ext' else 'extensions' end";

type TenantPool = (String, Pool, Arc<TenantLayout>);

#[derive(Default)]
pub struct Pools {
	pools: RwLock<HashMap<String, TenantPool>>,
	max_connections: usize,
	statement_timeout_ms: u64,
}

impl Pools {
	pub fn new(max_connections: usize, statement_timeout_ms: u64) -> Self {
		Self {
			pools: RwLock::new(HashMap::new()),
			max_connections,
			statement_timeout_ms,
		}
	}

	async fn pool(
		&self,
		tenant: &str,
		database_url: &str,
	) -> Result<(Pool, Arc<TenantLayout>), StorageError> {
		if let Some((url, pool, layout)) = self.pools.read().await.get(tenant)
			&& url == database_url
		{
			return Ok((pool.clone(), layout.clone()));
		}
		let config: tokio_postgres::Config = database_url.parse().map_err(|error| {
			tracing::error!(tenant, %error, "tenant database_url");
			StorageError::internal()
		})?;
		// Built with the old names first, asked which names it has, and built again only when it
		// has the new ones: the search path is a connection option, set before any connection.
		let old = TenantLayout::default();
		let mut pool = self.build(tenant, config.clone(), &old)?;
		let layout = {
			let client = pool.get().await.map_err(|error| {
				tracing::error!(tenant, %error, "tenant connection");
				StorageError::database_timeout()
			})?;
			let row = client
				.query_one(LAYOUT_SQL, &[])
				.await
				.map_err(|e| map_pg_error(&e))?;
			TenantLayout {
				has_new_roles: row.get(0),
				schema: row.get(1),
				extensions: row.get(2),
			}
		};
		if layout.search_path() != old.search_path() {
			pool.close();
			pool = self.build(tenant, config, &layout)?;
		}
		let layout = Arc::new(layout);
		self.pools.write().await.insert(
			tenant.to_string(),
			(database_url.to_string(), pool.clone(), layout.clone()),
		);
		Ok((pool, layout))
	}

	fn build(
		&self,
		tenant: &str,
		mut config: tokio_postgres::Config,
		layout: &TenantLayout,
	) -> Result<Pool, StorageError> {
		// The search path, on the connection.
		config.options(format!("-c search_path={}", layout.search_path()));
		let manager = Manager::from_config(
			config,
			NoTls,
			ManagerConfig {
				recycling_method: RecyclingMethod::Fast,
			},
		);
		Pool::builder(manager)
			.max_size(self.max_connections.max(1))
			.runtime(Runtime::Tokio1)
			.build()
			.map_err(|error| {
				tracing::error!(tenant, %error, "tenant pool");
				StorageError::internal()
			})
	}

	/// Drops a tenant's connections: its credentials changed or it left the host.
	pub async fn forget(&self, tenant: &str) {
		if let Some((_, pool, _)) = self.pools.write().await.remove(tenant) {
			pool.close();
		}
	}

	/// A transaction in the tenant's database, already become the caller.
	pub async fn begin(
		&self,
		tenant: &str,
		database_url: &str,
		caller: &Caller,
		facts: &RequestFacts,
	) -> Result<Scope, StorageError> {
		let (pool, layout) = self.pool(tenant, database_url).await?;
		let client = pool.get().await.map_err(|error| {
			tracing::error!(tenant, %error, "tenant connection");
			StorageError::database_timeout()
		})?;
		let mut scope = Scope {
			client: Some(client),
			open: false,
			layout,
		};
		scope.execute_batch("BEGIN").await?;
		scope.open = true;
		if self.statement_timeout_ms > 0 {
			scope
				.execute_batch(&format!(
					"SET LOCAL statement_timeout TO '{}ms'",
					self.statement_timeout_ms
				))
				.await?;
		}
		scope.become_caller(caller, facts).await?;
		Ok(scope)
	}
}

/// An open transaction. Commit it, or it is abandoned: dropping an unfinished one closes its
/// connection rather than handing a half-done transaction back to the pool, and Postgres rolls
/// back a transaction whose connection went away.
pub struct Scope {
	client: Option<Object>,
	open: bool,
	layout: Arc<TenantLayout>,
}

impl Scope {
	/// The storage schema's name in this database (`snout_files` or `storage`), for a statement
	/// that names it.
	pub fn schema(&self) -> &str {
		&self.layout.schema
	}

	fn client(&self) -> Result<&Object, StorageError> {
		self.client.as_ref().ok_or_else(StorageError::internal)
	}

	/// Become `caller` for the rest of this transaction. Called again with
	/// another caller to switch, as its `asSuperUser()` does inside one transaction.
	pub async fn become_caller(
		&self,
		caller: &Caller,
		facts: &RequestFacts,
	) -> Result<(), StorageError> {
		// The role the claim names, as the data API runs it (`layout::role_to_run`): an old name
		// as the alias role it is where the new names exist, a new name as the old one where they
		// do not. In the role, the role claim and the claims alike, so a policy sees one name.
		let role = layout::role_to_run(&caller.role, self.layout.has_new_roles).to_string();
		let mut claims = caller.claims.clone();
		if claims.get("role").and_then(Value::as_str) == Some(caller.role.as_str()) {
			claims.insert("role".into(), Value::String(role.clone()));
		}
		let claims = Value::Object(claims).to_string();
		let headers = Value::Object(facts.headers.clone()).to_string();
		let sub = caller.sub().unwrap_or("").to_string();
		self.query(
			"SELECT set_config('role', $1, true), set_config('request.jwt.claim.role', $2, true), set_config('request.jwt', $3, true), \
			 set_config('request.jwt.claim.sub', $4, true), set_config('request.jwt.claims', $5, true), set_config('request.headers', $6, true), \
			 set_config('request.method', $7, true), set_config('request.path', $8, true), set_config('storage.operation', $9, true), \
			 set_config('storage.allow_delete_query', 'true', true)",
			&[&role, &role, &caller.jwt, &sub, &claims, &headers, &facts.method, &facts.path, &facts.operation],
		)
		.await?;
		Ok(())
	}

	// Every statement goes through one of the four below, which is where it is put in this
	// database's names (`TenantLayout::sql`).

	pub async fn execute_batch(&mut self, sql: &str) -> Result<(), StorageError> {
		self.client()?
			.batch_execute(&self.layout.sql(sql))
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn query(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<Vec<tokio_postgres::Row>, StorageError> {
		self.client()?
			.query(&*self.layout.sql(sql), params)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn query_opt(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<Option<tokio_postgres::Row>, StorageError> {
		self.client()?
			.query_opt(&*self.layout.sql(sql), params)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn execute(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<u64, StorageError> {
		self.client()?
			.execute(&*self.layout.sql(sql), params)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn commit(mut self) -> Result<(), StorageError> {
		self.execute_batch("COMMIT").await?;
		self.open = false;
		Ok(())
	}

	pub async fn rollback(mut self) -> Result<(), StorageError> {
		self.execute_batch("ROLLBACK").await?;
		self.open = false;
		Ok(())
	}
}

impl Drop for Scope {
	fn drop(&mut self) {
		if self.open
			&& let Some(client) = self.client.take()
		{
			// Detached from the pool and dropped: the connection closes, the transaction with it.
			drop(Object::take(client));
		}
	}
}

/// Shared by every route.
pub type SharedPools = Arc<Pools>;

#[cfg(test)]
mod tests {
	use super::TenantLayout;

	#[test]
	fn the_search_path_takes_the_names_the_database_has() {
		assert_eq!(
			TenantLayout::default().search_path(),
			"storage,public,extensions"
		);
		let renamed = TenantLayout {
			has_new_roles: true,
			schema: "snout_files".into(),
			extensions: "snout_ext".into(),
		};
		assert_eq!(renamed.search_path(), "snout_files,public,snout_ext");
	}

	#[test]
	fn statements_take_the_names_the_database_has() {
		let sql = "INSERT INTO objects (bucket_id, name) VALUES ($1, $2) ON CONFLICT (bucket_id, name) \
			DO UPDATE SET user_metadata = objects.user_metadata RETURNING (SELECT public FROM buckets WHERE id = $1), \
			set_config('storage.operation', 'storage.object.upload', true)";
		let old = TenantLayout::default();
		assert!(!old.is_new());
		assert!(matches!(old.sql(sql), std::borrow::Cow::Borrowed(_)));
		let renamed = TenantLayout {
			has_new_roles: true,
			schema: "snout_files".into(),
			extensions: "snout_ext".into(),
		};
		assert!(renamed.is_new());
		assert_eq!(
			renamed.sql(sql),
			"INSERT INTO files (bucket_id, name) VALUES ($1, $2) ON CONFLICT (bucket_id, name) \
			DO UPDATE SET user_metadata = files.user_metadata RETURNING (SELECT public FROM spaces WHERE id = $1), \
			set_config('storage.operation', 'storage.object.upload', true)"
		);
		assert_eq!(
			renamed.sql("SELECT 1 FROM snout_files.objects o WHERE o.bucket_id = $1"),
			"SELECT 1 FROM snout_files.files o WHERE o.bucket_id = $1"
		);
	}
}
