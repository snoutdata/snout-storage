//! snout-storage: file storage for Postgres-backed apps, over S3, with row-level security deciding access.
//!
//! The storage HTTP API that existing JavaScript clients speak. Same routes,
//! same `storage` schema, same S3 key layout (`<tenant>/<bucket>/<name>/<version>`), same tenant
//! rows in the metadata database. It does not serve the S3-protocol endpoint.
//!
//! **The security core:** every object operation runs in the customer's own database AS THE
//! CALLER (`db.rs`: the role and the JWT claims set for the transaction), so their row-level
//! security policies decide. This server never decides access itself.

pub mod app;
pub mod config;
pub mod crypto;
pub mod db;
pub mod error;
pub mod jwt;
pub mod limits;
pub mod migration_files;
pub mod migrations;
pub mod objects;
pub mod render;
pub mod s3;
pub mod sigv4;
pub mod tenants;
pub mod tus;
