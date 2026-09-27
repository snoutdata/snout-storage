-- The metadata database: one row per project this server serves, written by the admin API.
--
-- The secrets (the two API keys, the JWT secret, the database URL) and the URL-signing keys are
-- stored encrypted with AUTH_ENCRYPTION_KEY; nothing here is readable without it.

CREATE TABLE tenants (
	id text PRIMARY KEY,
	anon_key text NOT NULL,
	service_key text NOT NULL,
	jwt_secret text NOT NULL,
	database_url text NOT NULL,
	file_size_limit bigint NOT NULL DEFAULT 52428800,
	feature_image_transformation boolean NOT NULL DEFAULT false,
	image_transformation_max_resolution integer,
	-- The last migration run against the project's database, and whether it finished.
	migrations_version text,
	migrations_status text,
	created_at timestamptz NOT NULL DEFAULT now()
);

-- Keys the server signs its own URLs with (signed download and upload URLs), one active per kind.
CREATE TABLE tenants_jwks (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	tenant_id text NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
	kind text NOT NULL,
	content text NOT NULL,
	active boolean NOT NULL DEFAULT true,
	created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tenants_jwks_tenant ON tenants_jwks (tenant_id) WHERE active;
-- A second registration keeps the first key, so URLs already handed out stay valid.
CREATE UNIQUE INDEX tenants_jwks_one_signing_key ON tenants_jwks (tenant_id)
	WHERE active AND kind = 'storage-url-signing-key';
