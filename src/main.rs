//! The snout-storage binary. Wiring only; everything it runs is in the library.
//!
//!   snout-storage                                  serve (the public port and the admin port)
//!   snout-storage migrate-tenant <database-url>    the storage schema in a project's database
//!   snout-storage migrate-metadata <database-url>  the tenants table in the metadata database

use std::sync::Arc;

use snout_storage::app::{App, admin_router, public_router};
use snout_storage::config::Config;
use snout_storage::db::Pools;
use snout_storage::migration_files::{METADATA, TENANT};
use snout_storage::migrations::{Roles, Target, migrate};
use snout_storage::s3::{S3, S3Options};
use snout_storage::tenants::Registry;

fn roles(config: &Config) -> Roles {
	Roles {
		install_roles: config.install_roles,
		anon: config.anon_role.clone(),
		authenticated: config.authenticated_role.clone(),
		service: config.service_role.clone(),
		super_user: config.super_user.clone(),
	}
}

async fn serve() -> Result<(), String> {
	let config = Config::from_env().map_err(|e| e.to_string())?;
	let registry = Registry::new(&config.metadata_url, &config.encryption_key, roles(&config))
		.map_err(|e| e.message)?;
	// At start: the metadata database's own schema first.
	registry
		.migrate_metadata()
		.await
		.map_err(|e| format!("metadata migrations: {}", e.message))?;
	let pools = Pools::new(config.max_connections, config.statement_timeout_ms);
	let s3 = S3::new(S3Options {
		bucket: config.s3.bucket.clone(),
		region: config.s3.region.clone(),
		endpoint: config.s3.endpoint.clone(),
		force_path_style: config.s3.force_path_style,
		part_size: config.s3.part_size,
		queue_size: config.s3.queue_size,
		accept_invalid_certs: config.s3.accept_invalid_certs,
	})?;
	let public = format!("{}:{}", config.host, config.port);
	let admin = format!("{}:{}", config.host, config.admin_port);
	let app = Arc::new(App {
		config,
		registry,
		pools,
		s3,
	});

	let public_listener = tokio::net::TcpListener::bind(&public)
		.await
		.map_err(|e| format!("{public}: {e}"))?;
	let admin_listener = tokio::net::TcpListener::bind(&admin)
		.await
		.map_err(|e| format!("{admin}: {e}"))?;
	tracing::info!(%public, %admin, "snout-storage listening");
	let public_server = axum::serve(public_listener, public_router(app.clone()));
	let admin_server = axum::serve(admin_listener, admin_router(app));
	tokio::select! {
		result = public_server => result.map_err(|e| e.to_string()),
		result = admin_server => result.map_err(|e| e.to_string()),
		_ = tokio::signal::ctrl_c() => Ok(()),
	}
}

async fn migrate_one(command: &str, url: &str) -> Result<(), String> {
	let (files, target) = if command == "migrate-tenant" {
		(TENANT, Target::Tenant)
	} else {
		(METADATA, Target::Metadata)
	};
	let (mut client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
		.await
		.map_err(|e| format!("cannot connect: {e}"))?;
	tokio::spawn(async move {
		let _ = connection.await;
	});
	let ran = migrate(&mut client, files, target, &Roles::default())
		.await
		.map_err(|e| e.to_string())?;
	println!("ran {} migration(s): {:?}", ran.len(), ran);
	Ok(())
}

#[tokio::main]
async fn main() {
	tracing_subscriber::fmt()
		.with_env_filter(
			tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
		)
		.json()
		.init();
	let args: Vec<String> = std::env::args().collect();
	let result = match args.get(1).map(String::as_str) {
		None | Some("serve") => serve().await,
		Some(command @ ("migrate-tenant" | "migrate-metadata")) => match args.get(2) {
			Some(url) => migrate_one(command, url).await,
			None => Err(format!("usage: snout-storage {command} <database-url>")),
		},
		Some(other) => Err(format!(
			"unknown command {other}; see the header of main.rs"
		)),
	};
	if let Err(message) = result {
		eprintln!("{message}");
		std::process::exit(1);
	}
}
