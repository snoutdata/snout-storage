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

use std::collections::HashMap;
use std::sync::Arc;

use deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod, Runtime};
use serde_json::{Map, Value};
use tokio::sync::RwLock;
use tokio_postgres::NoTls;
use tokio_postgres::types::ToSql;

use crate::error::StorageError;
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

#[derive(Default)]
pub struct Pools {
	pools: RwLock<HashMap<String, (String, Pool)>>,
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

	async fn pool(&self, tenant: &str, database_url: &str) -> Result<Pool, StorageError> {
		if let Some((url, pool)) = self.pools.read().await.get(tenant)
			&& url == database_url
		{
			return Ok(pool.clone());
		}
		let mut config: tokio_postgres::Config = database_url.parse().map_err(|error| {
			tracing::error!(tenant, %error, "tenant database_url");
			StorageError::internal()
		})?;
		// The search path, on the connection.
		config.options(format!("-c search_path={}", SEARCH_PATH.replace(' ', "")));
		let manager = Manager::from_config(
			config,
			NoTls,
			ManagerConfig {
				recycling_method: RecyclingMethod::Fast,
			},
		);
		let pool = Pool::builder(manager)
			.max_size(self.max_connections.max(1))
			.runtime(Runtime::Tokio1)
			.build()
			.map_err(|error| {
				tracing::error!(tenant, %error, "tenant pool");
				StorageError::internal()
			})?;
		self.pools
			.write()
			.await
			.insert(tenant.to_string(), (database_url.to_string(), pool.clone()));
		Ok(pool)
	}

	/// Drops a tenant's connections: its credentials changed or it left the host.
	pub async fn forget(&self, tenant: &str) {
		if let Some((_, pool)) = self.pools.write().await.remove(tenant) {
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
		let pool = self.pool(tenant, database_url).await?;
		let client = pool.get().await.map_err(|error| {
			tracing::error!(tenant, %error, "tenant connection");
			StorageError::database_timeout()
		})?;
		let mut scope = Scope {
			client: Some(client),
			open: false,
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

	/// The same, as the tenant's own storage admin with no caller: for the few operations
	/// Runs "as super user", e.g. reading a bucket's limits.
	pub async fn begin_super(
		&self,
		tenant: &str,
		database_url: &str,
	) -> Result<Scope, StorageError> {
		let pool = self.pool(tenant, database_url).await?;
		let client = pool.get().await.map_err(|_| StorageError::internal())?;
		let mut scope = Scope {
			client: Some(client),
			open: false,
		};
		scope.execute_batch("BEGIN").await?;
		scope.open = true;
		Ok(scope)
	}
}

/// An open transaction. Commit it, or it is abandoned: dropping an unfinished one closes its
/// connection rather than handing a half-done transaction back to the pool, and Postgres rolls
/// back a transaction whose connection went away.
pub struct Scope {
	client: Option<Object>,
	open: bool,
}

impl Scope {
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
		let claims = Value::Object(caller.claims.clone()).to_string();
		let headers = Value::Object(facts.headers.clone()).to_string();
		let sub = caller.sub().unwrap_or("").to_string();
		self.query(
			"SELECT set_config('role', $1, true), set_config('request.jwt.claim.role', $2, true), set_config('request.jwt', $3, true), \
			 set_config('request.jwt.claim.sub', $4, true), set_config('request.jwt.claims', $5, true), set_config('request.headers', $6, true), \
			 set_config('request.method', $7, true), set_config('request.path', $8, true), set_config('storage.operation', $9, true), \
			 set_config('storage.allow_delete_query', 'true', true)",
			&[&caller.role, &caller.role, &caller.jwt, &sub, &claims, &headers, &facts.method, &facts.path, &facts.operation],
		)
		.await?;
		Ok(())
	}

	pub async fn execute_batch(&mut self, sql: &str) -> Result<(), StorageError> {
		self.client()?
			.batch_execute(sql)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn query(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<Vec<tokio_postgres::Row>, StorageError> {
		self.client()?
			.query(sql, params)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn query_opt(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<Option<tokio_postgres::Row>, StorageError> {
		self.client()?
			.query_opt(sql, params)
			.await
			.map_err(|e| map_pg_error(&e))
	}

	pub async fn execute(
		&self,
		sql: &str,
		params: &[&(dyn ToSql + Sync)],
	) -> Result<u64, StorageError> {
		self.client()?
			.execute(sql, params)
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
