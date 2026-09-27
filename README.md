# snout-storage

File storage for Postgres-backed apps: buckets and files kept in S3 (or anything S3-compatible),
indexed in the project's own Postgres, with the project's **row-level security policies deciding
who may read, write or delete what**. One static binary, written in Rust. It runs every project
on a SnoutData Cloud host.

- **Your policies decide.** Every file operation runs in the project's own database as the
  caller, against `storage.objects` and `storage.buckets`, so an ordinary Postgres policy is the
  whole of the access control. The server never decides access itself.
- **Everything a file API needs:** buckets (public or private, per-bucket size and type limits),
  upload (binary, multipart form, or streamed), upsert, download with byte ranges and caching
  headers, move, copy, delete, list (by level, or paginated with a cursor), signed download and
  upload URLs, resumable uploads (tus 1.0.0), and image resizing through
  [imgproxy](https://github.com/imgproxy/imgproxy).
- **Many projects, one process.** A tenant (a project) is registered through an admin API with
  its database URL and keys; requests are routed to it by host name.
- **Small.** A 15 MB image; under 1 MB of memory at idle and a few MB under load; ready in about
  0.2 s. Uploads stream end to end in fixed-size parts, so memory does not grow with file size.

## The schema

`migrations/tenant/` creates the `storage` schema in each project's database: `buckets`,
`objects`, and a few helpers for policies (`storage.foldername(name)`, `storage.filename(name)`,
`storage.extension(name)`, `storage.operation()`). A policy that lets each user manage the files
under a folder named after them:

```sql
create policy "own files" on storage.objects for all to authenticated
	using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text)
	with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
```

`migrations/metadata/` creates the `tenants` table in the server's own metadata database. Each
migration runs once, in a transaction, and is recorded with its hash.

## Running it

```sh
docker build -f Containerfile -t snout-storage .
docker run -p 5000:5000 -p 5001:5001 \
  -e DATABASE_MULTITENANT_URL=postgres://storage_admin:secret@db:5432/storage_meta \
  -e SERVER_ADMIN_API_KEYS=an-admin-key \
  -e AUTH_ENCRYPTION_KEY=a-long-random-key \
  -e 'REQUEST_X_FORWARDED_HOST_REGEXP=^([a-z0-9]+)\.api\.example\.com$' \
  -e STORAGE_S3_BUCKET=my-bucket -e STORAGE_S3_REGION=us-east-1 \
  snout-storage
```

Port 5000 serves the storage API; port 5001 the admin API (`PUT /tenants/:id` registers a project,
authorised by `apikey: <SERVER_ADMIN_API_KEYS>`). The tenant is the first group of
`REQUEST_X_FORWARDED_HOST_REGEXP`, matched against `X-Forwarded-Host`.

| Setting | Default | |
|---|---|---|
| `DATABASE_MULTITENANT_URL` | required | the metadata database |
| `SERVER_ADMIN_API_KEYS` | required | comma-separated keys for the admin API |
| `AUTH_ENCRYPTION_KEY` | required | encrypts each tenant's keys and database URL at rest |
| `REQUEST_X_FORWARDED_HOST_REGEXP` | | which host names are tenants |
| `STORAGE_S3_BUCKET`, `STORAGE_S3_REGION` | | where files are kept (without a bucket the server starts and refuses uploads) |
| `STORAGE_S3_ENDPOINT`, `STORAGE_S3_FORCE_PATH_STYLE` | AWS | any S3-compatible store (MinIO, R2, ...) |
| `STORAGE_S3_UPLOAD_PART_SIZE`, `STORAGE_S3_UPLOAD_QUEUE_SIZE` | 16 MiB, 2 | streamed upload parts and how many are in flight |
| `UPLOAD_FILE_SIZE_LIMIT` | 50 MiB | the largest upload, before any tenant or bucket limit |
| `IMGPROXY_URL` | | enables image resizing |
| `DB_ANON_ROLE`, `DB_AUTHENTICATED_ROLE`, `DB_SERVICE_ROLE` | anon, authenticated, service_role | the roles a caller becomes |
| `DB_INSTALL_ROLES` | false | create those roles when missing |
| `DATABASE_MAX_CONNECTIONS`, `DATABASE_STATEMENT_TIMEOUT` | 20, 30000 ms | per tenant |
| `SERVER_PORT`, `SERVER_ADMIN_PORT` | 5000, 5001 | |

S3 credentials come from `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`, then a
`credential_process` in `AWS_CONFIG_FILE`, then the instance metadata service (IMDSv2).

## Development

`bash scripts/test.sh` runs the checks in a container; Docker or Podman is the only thing you need.
See [CONTRIBUTING.md](./CONTRIBUTING.md).

Licensed under the [Apache License 2.0](./LICENSE). Security reports: [SECURITY.md](./SECURITY.md).
