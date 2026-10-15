//! A project's database in either layout (the own layout) against a real Postgres: the
//! tenant migrations make `storage` with `buckets` and `objects`, or `snout_files` with `spaces`
//! and `files`, granted to the role names that database has, with the file's own hash in the
//! ledger; and a request's statements, written in the old names, run in either. Skips without
//! STORAGE_TEST_DATABASE_URL; `bash tests/db.sh` runs it with one.

use serde_json::{Map, Value, json};
use snout_storage::db::{Caller, Pools, RequestFacts};
use snout_storage::migration_files::TENANT;
use snout_storage::migrations::{Roles, Target, migrate};
use tokio_postgres::NoTls;

/// Roles are the cluster's: two tests creating them at once race, so one setup at a time.
static SETUP: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// A fresh database, prepared by `setup` (as the pod's bootstrap would), and its URL.
async fn database(admin_url: &str, name: &str, setup: &str) -> String {
	let (admin, connection) = tokio_postgres::connect(admin_url, NoTls).await.unwrap();
	tokio::spawn(connection);
	for statement in [
		format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
		format!("CREATE DATABASE {name}"),
	] {
		admin.batch_execute(&statement).await.unwrap();
	}
	let url = match admin_url.rsplit_once('/') {
		Some((base, _)) => format!("{base}/{name}"),
		None => unreachable!(),
	};
	let (client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
	tokio::spawn(connection);
	let _one_at_a_time = SETUP.lock().await;
	client.batch_execute(setup).await.unwrap();
	url
}

/// Roles are the cluster's, so both sets exist here; each database says which it is by its
/// schema, made in advance as a pod's bootstrap makes it.
const ROLES: &str = "DO $$ BEGIN
		IF to_regrole('anon') IS NULL THEN CREATE ROLE anon NOLOGIN NOINHERIT; END IF;
		IF to_regrole('authenticated') IS NULL THEN CREATE ROLE authenticated NOLOGIN NOINHERIT; END IF;
		IF to_regrole('service_role') IS NULL THEN CREATE ROLE service_role NOLOGIN NOINHERIT BYPASSRLS; END IF;
		IF to_regrole('snout_app') IS NULL THEN CREATE ROLE snout_app NOLOGIN NOINHERIT; END IF;
		IF to_regrole('snout_member') IS NULL THEN CREATE ROLE snout_member NOLOGIN NOINHERIT; END IF;
		IF to_regrole('snout_server') IS NULL THEN CREATE ROLE snout_server NOLOGIN NOINHERIT BYPASSRLS; END IF;
	END $$;
	GRANT snout_app TO anon WITH INHERIT TRUE;
	GRANT snout_member TO authenticated WITH INHERIT TRUE;
	GRANT snout_server TO service_role WITH INHERIT TRUE;";

fn caller(role: &str) -> Caller {
	let claims: Map<String, Value> = json!({ "role": role, "sub": "u1" })
		.as_object()
		.cloned()
		.unwrap_or_default();
	Caller::from_claims(String::new(), claims)
}

#[tokio::test]
async fn either_layout_is_made_and_spoken_to_in_its_own_names() {
	let Ok(admin_url) = std::env::var("STORAGE_TEST_DATABASE_URL") else {
		eprintln!("skipped: STORAGE_TEST_DATABASE_URL is not set (tests/db.sh sets it)");
		return;
	};
	let pid = std::process::id();
	let roles = ROLES;
	for (layout, schema, spaces, files, member, server) in [
		(
			"old",
			"storage",
			"buckets",
			"objects",
			"authenticated",
			"service_role",
		),
		(
			"new",
			"snout_files",
			"spaces",
			"files",
			"snout_member",
			"snout_server",
		),
	] {
		let name = format!("storage_layout_{layout}_{pid}");
		let url = database(
			&admin_url,
			&name,
			&format!("{roles} CREATE SCHEMA {schema};"),
		)
		.await;
		let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
		tokio::spawn(connection);
		let ran = migrate(&mut client, TENANT, Target::Tenant, &Roles::default())
			.await
			.unwrap();
		assert_eq!(ran, [1], "{layout}");
		assert!(
			migrate(&mut client, TENANT, Target::Tenant, &Roles::default())
				.await
				.unwrap()
				.is_empty(),
			"{layout}: a second run runs nothing"
		);
		let row = client
			.query_one(
				&format!(
					"SELECT to_regclass('{schema}.{spaces}') IS NOT NULL, to_regclass('{schema}.{files}') IS NOT NULL,
					 has_table_privilege('{member}', '{schema}.{files}', 'SELECT'),
					 has_table_privilege('{server}', '{schema}.{spaces}', 'INSERT'),
					 has_schema_privilege('{member}', '{schema}', 'USAGE'),
					 (SELECT hash FROM {schema}.migrations WHERE id = 1)"
				),
				&[],
			)
			.await
			.unwrap();
		for i in 0..5 {
			assert!(row.get::<_, bool>(i), "{layout}: column {i}");
		}
		assert_eq!(row.get::<_, String>(5), TENANT[0].hash(), "{layout}");
		if layout == "new" {
			let old_names: bool = client
				.query_one(
					"SELECT to_regnamespace('storage') IS NULL AND NOT EXISTS (SELECT FROM pg_class c, aclexplode(c.relacl) a \
					 WHERE c.oid = 'snout_files.files'::regclass AND a.grantee = 'authenticated'::regrole)",
					&[],
				)
				.await
				.unwrap()
				.get(0);
			assert!(old_names, "grants go to the new names only");
		}

		// A request, its statements in the old names, in either database; the claim in either
		// vocabulary.
		let pools = Pools::new(2, 0);
		let facts = RequestFacts::default();
		let scope = pools
			.begin(&name, &url, &caller("snout_server"), &facts)
			.await
			.unwrap();
		assert_eq!(scope.schema(), schema);
		scope
			.execute("INSERT INTO buckets (id, name) VALUES ('b', 'b')", &[])
			.await
			.unwrap();
		scope
			.execute(
				"INSERT INTO objects (bucket_id, name, version) VALUES ('b', 'a/c.png', '1') \
				 ON CONFLICT (bucket_id, name) DO UPDATE SET user_metadata = objects.user_metadata",
				&[],
			)
			.await
			.unwrap();
		let found = scope
			.query_opt(
				"SELECT o.name, storage.extension(o.name) FROM objects o JOIN buckets b ON b.id = o.bucket_id WHERE b.public = false",
				&[],
			)
			.await
			.unwrap()
			.map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)));
		assert_eq!(found, Some(("a/c.png".into(), "png".into())), "{layout}");
		scope.commit().await.unwrap();
		// A signed-in caller, in the old vocabulary, with no policy: sees nothing.
		let scope = pools
			.begin(&name, &url, &caller("authenticated"), &facts)
			.await
			.unwrap();
		let seen = scope
			.query("SELECT 1 FROM objects", &[])
			.await
			.unwrap()
			.len();
		assert_eq!(seen, 0, "{layout}");
		scope.rollback().await.unwrap();
		// The server key in the old vocabulary: in the new layout it runs as the alias, which
		// inherits the new role's grants and carries BYPASSRLS itself, as through the data API.
		let scope = pools
			.begin(&name, &url, &caller("service_role"), &facts)
			.await
			.unwrap();
		let role: String = scope
			.query_opt("SELECT current_user::text FROM objects", &[])
			.await
			.unwrap()
			.map(|r| r.get(0))
			.unwrap_or_default();
		assert_eq!(role, "service_role", "{layout}");
		scope.rollback().await.unwrap();
		pools.forget(&name).await;
		drop(client);
	}
}

/// A database an earlier release migrated (the file in the old layout's names, its hash in the
/// ledger), in either layout, is neither refused nor migrated again by this one.
#[tokio::test]
async fn a_database_migrated_by_an_earlier_release_is_left_alone() {
	let Ok(admin_url) = std::env::var("STORAGE_TEST_DATABASE_URL") else {
		eprintln!("skipped: STORAGE_TEST_DATABASE_URL is not set (tests/db.sh sets it)");
		return;
	};
	let pid = std::process::id();
	let released = TENANT[0].released_as[0];
	for (layout, schema, new) in [("old", "storage", false), ("new", "snout_files", true)] {
		let name = format!("storage_released_{layout}_{pid}");
		// What the earlier release did: the same statements, in this layout's names, and the
		// hash of the file it carried.
		let url = database(
			&admin_url,
			&name,
			&format!(
				"{ROLES} CREATE SCHEMA {schema}; SET search_path TO {schema}, public;
				 CREATE TABLE {schema}.migrations (id integer PRIMARY KEY, name text NOT NULL, hash text NOT NULL,
				 executed_at timestamptz NOT NULL DEFAULT now());
				 {}
				 INSERT INTO {schema}.migrations (id, name, hash) VALUES (1, 'storage', '{released}');",
				TENANT[0].sql_for(new)
			),
		)
		.await;
		let (mut client, connection) = tokio_postgres::connect(&url, NoTls).await.unwrap();
		tokio::spawn(connection);
		let ran = migrate(&mut client, TENANT, Target::Tenant, &Roles::default())
			.await
			.unwrap_or_else(|e| panic!("{layout}: {e}"));
		assert!(ran.is_empty(), "{layout}: ran {ran:?} again");
		let hash: String = client
			.query_one(
				&format!("SELECT hash FROM {schema}.migrations WHERE id = 1"),
				&[],
			)
			.await
			.unwrap()
			.get(0);
		assert_eq!(hash, released, "{layout}: the ledger is left as it was");
	}
}
