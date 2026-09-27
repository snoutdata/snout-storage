# snout-storage's image: one static binary on Alpine.
#
#   docker buildx build -f Containerfile --platform linux/arm64 -t snout-storage .
#
# The context is the repository root, for its lockfile (in the SnoutData monorepo, the stack
# workspace: `-f storage/Containerfile packages/stack`). Alpine rather than scratch
# for one reason: the host agent refreshes the S3 credentials by running a small `sh` script in
# the container, so a shell, `mkdir`, `cat` and `mv` must be there.
FROM docker.io/library/rust:1.98.1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --locked --release -p snout-storage \
	&& cp target/release/snout-storage /snout-storage

FROM docker.io/library/alpine:3.20
RUN adduser -D -H -u 1000 storage
COPY --from=build /snout-storage /usr/local/bin/snout-storage
USER storage
EXPOSE 5000 5001
ENTRYPOINT ["/usr/local/bin/snout-storage"]
CMD ["serve"]
