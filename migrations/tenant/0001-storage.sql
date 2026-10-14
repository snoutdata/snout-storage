-- The storage schema in a project's database: its buckets, and the objects in them.
--
-- Every object operation runs AS THE CALLER against these two tables, so the project's own
-- row-level security policies decide who may read, write or delete what. The server never decides
-- access itself; it only asks the database.
--
-- The schema itself is expected to exist already, owned by the role this server connects as, so
-- that role needs no CREATE on the database (the runner creates it only when it is missing). Role
-- names come from the settings the runner sets first (storage.anon_role, storage.authenticated_role,
-- storage.service_role, storage.super_user), and with storage.install_roles = 'true' the three API
-- roles are created when missing.

DO $$
DECLARE
	anon text := coalesce(nullif(current_setting('storage.anon_role', true), ''), 'anon');
	authed text := coalesce(nullif(current_setting('storage.authenticated_role', true), ''), 'authenticated');
	service text := coalesce(nullif(current_setting('storage.service_role', true), ''), 'service_role');
BEGIN
	IF coalesce(current_setting('storage.install_roles', true), 'false') = 'true' THEN
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = anon) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', anon);
		END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = authed) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT', authed);
		END IF;
		IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = service) THEN
			EXECUTE format('CREATE ROLE %I NOLOGIN NOINHERIT BYPASSRLS', service);
		END IF;
	END IF;
END
$$;

CREATE TABLE storage.buckets (
	id text PRIMARY KEY,
	name text NOT NULL,
	-- The creator. `owner` is the auth user's id as a uuid; `owner_id` is the same subject as text,
	-- which also holds a subject that is not a uuid. New code reads `owner_id`.
	owner uuid,
	owner_id text,
	public boolean NOT NULL DEFAULT false,
	-- NULL means no limit of the bucket's own (the project's limit still applies).
	file_size_limit bigint,
	-- NULL means any type; entries may end in `/*` (`image/*`).
	allowed_mime_types text[],
	type text NOT NULL DEFAULT 'STANDARD',
	created_at timestamptz DEFAULT now(),
	updated_at timestamptz DEFAULT now()
);
CREATE UNIQUE INDEX buckets_name ON storage.buckets (name);

CREATE TABLE storage.objects (
	id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	bucket_id text REFERENCES storage.buckets (id),
	-- The key within the bucket, `/`-separated. Folders are not rows: a folder is a common prefix.
	name text,
	owner uuid,
	owner_id text,
	-- Which stored copy is current. The file in object storage lives at
	-- `<project>/<bucket>/<name>/<version>`, so replacing an object writes a new copy first and
	-- only then moves this pointer; a reader never sees half a file.
	version text,
	-- What the server recorded (size, mimetype, eTag, cacheControl, lastModified, ...).
	metadata jsonb,
	-- What the uploader attached, readable by policies (the INSERT sees it whole).
	user_metadata jsonb,
	path_tokens text[] GENERATED ALWAYS AS (string_to_array(name, '/')) STORED,
	created_at timestamptz DEFAULT now(),
	updated_at timestamptz DEFAULT now(),
	last_accessed_at timestamptz DEFAULT now()
);
CREATE UNIQUE INDEX objects_bucket_name ON storage.objects (bucket_id, name);
-- Listing walks keys in byte order, and the case-insensitive listing in byte order of lower().
CREATE INDEX objects_bucket_name_bytes ON storage.objects (bucket_id, name COLLATE "C");
CREATE INDEX objects_bucket_lower_name_bytes ON storage.objects (bucket_id, lower(name) COLLATE "C");

CREATE FUNCTION storage.touch_updated_at() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	NEW.updated_at := now();
	RETURN NEW;
END
$$;
CREATE TRIGGER objects_touch_updated_at BEFORE UPDATE ON storage.objects
	FOR EACH ROW EXECUTE FUNCTION storage.touch_updated_at();

CREATE FUNCTION storage.check_bucket_name() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	IF length(NEW.name) > 100 THEN
		RAISE EXCEPTION 'bucket name "%" is too long (% characters). Max is 100.', NEW.name, length(NEW.name);
	END IF;
	RETURN NEW;
END
$$;
CREATE TRIGGER buckets_check_name BEFORE INSERT OR UPDATE OF name ON storage.buckets
	FOR EACH ROW EXECUTE FUNCTION storage.check_bucket_name();

-- A row deleted by hand leaves its file in object storage with nothing pointing at it. Deletes go
-- through the server, which sets storage.allow_delete_query for its own transactions only.
CREATE FUNCTION storage.guard_delete() RETURNS trigger
	LANGUAGE plpgsql
	AS $$
BEGIN
	IF coalesce(current_setting('storage.allow_delete_query', true), 'false') <> 'true' THEN
		RAISE EXCEPTION 'Direct deletion from storage tables is not allowed. Use the Storage API instead.'
			USING HINT = 'This prevents accidental data loss from orphaned objects.', ERRCODE = '42501';
	END IF;
	RETURN NULL;
END
$$;
CREATE TRIGGER buckets_guard_delete BEFORE DELETE ON storage.buckets
	FOR EACH STATEMENT EXECUTE FUNCTION storage.guard_delete();
CREATE TRIGGER objects_guard_delete BEFORE DELETE ON storage.objects
	FOR EACH STATEMENT EXECUTE FUNCTION storage.guard_delete();

-- Helpers for policies. `name` is an object's key.

-- The folders a key sits in: 'a/b/c.png' gives {a,b}, 'c.png' gives {}.
CREATE FUNCTION storage.foldername(name text) RETURNS text[]
	LANGUAGE sql IMMUTABLE
	AS $$
	SELECT parts[1:cardinality(parts) - 1] FROM string_to_array(name, '/') AS parts
$$;

-- The last segment of a key: 'a/b/c.png' gives 'c.png'.
CREATE FUNCTION storage.filename(name text) RETURNS text
	LANGUAGE sql IMMUTABLE
	AS $$
	SELECT parts[cardinality(parts)] FROM string_to_array(name, '/') AS parts
$$;

-- What follows the last dot of the file name: 'a/c.tar.gz' gives 'gz'. A name without a dot gives
-- the whole name.
CREATE FUNCTION storage.extension(name text) RETURNS text
	LANGUAGE sql IMMUTABLE
	AS $$
	SELECT reverse(split_part(reverse(storage.filename(name)), '.', 1))
$$;

-- The operation the server is performing for this request ('storage.object.upload', ...), so a
-- policy can allow, say, reads without allowing lists.
CREATE FUNCTION storage.operation() RETURNS text
	LANGUAGE sql STABLE
	AS $$
	SELECT current_setting('storage.operation', true)
$$;

CREATE FUNCTION storage.allow_only_operation(expected_operation text) RETURNS boolean
	LANGUAGE sql STABLE
	AS $$
	SELECT storage.operation() = expected_operation
$$;

CREATE FUNCTION storage.allow_any_operation(expected_operations text[]) RETURNS boolean
	LANGUAGE sql STABLE
	AS $$
	SELECT storage.operation() = ANY (expected_operations)
$$;

-- Bytes stored per bucket, from what the server recorded.
CREATE FUNCTION storage.get_size_by_bucket() RETURNS TABLE (size bigint, bucket_id text)
	LANGUAGE sql STABLE
	AS $$
	SELECT sum((o.metadata ->> 'size')::bigint)::bigint, o.bucket_id FROM storage.objects o GROUP BY o.bucket_id
$$;

ALTER TABLE storage.buckets ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE storage.migrations ENABLE ROW LEVEL SECURITY;

DO $$
DECLARE
	anon text := coalesce(nullif(current_setting('storage.anon_role', true), ''), 'anon');
	authed text := coalesce(nullif(current_setting('storage.authenticated_role', true), ''), 'authenticated');
	service text := coalesce(nullif(current_setting('storage.service_role', true), ''), 'service_role');
	super text := coalesce(nullif(current_setting('storage.super_user', true), ''), 'postgres');
BEGIN
	EXECUTE format('GRANT USAGE ON SCHEMA storage TO %I, %I, %I', anon, authed, service);
	-- Everything; row-level security is what narrows it.
	EXECUTE format('GRANT ALL ON storage.buckets, storage.objects TO %I, %I, %I', anon, authed, service);
	IF EXISTS (SELECT FROM pg_roles WHERE rolname = super) THEN
		EXECUTE format('GRANT USAGE ON SCHEMA storage TO %I', super);
		EXECUTE format('GRANT ALL ON storage.buckets, storage.objects TO %I WITH GRANT OPTION', super);
	END IF;
END
$$;
