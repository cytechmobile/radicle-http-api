# Builds release binaries for Radicle.
FROM rust:1.81-alpine3.20 as builder
WORKDIR /src
COPY . .

# These arguments are necessary for the build to be reproducible.
ARG TZ
ARG LC_ALL
ARG SOURCE_DATE_EPOCH
ARG RADICLE_VERSION
ARG GIT_HEAD

# Copy cargo configuration we're going to use to specify compiler options.
RUN mkdir -p .cargo && cp build/config.toml .cargo/config.toml
# Install dependencies.
RUN apk update && apk add --no-cache git musl-dev xz asciidoctor zig
# Build man pages and strip metadata. Removes all comments, since they include
# non-reproducible information, such as version numbers.
RUN asciidoctor --doctype manpage --backend manpage --destination-dir . *.1.adoc && \
    find . -maxdepth 1 -type f -name '*.1' -exec sed -i '/^.\\\"/d' '{}' \;
# Add cargo targets.
RUN rustup target add \
    x86_64-unknown-linux-musl \
    aarch64-unknown-linux-musl \
    x86_64-apple-darwin \
    aarch64-apple-darwin

# Install dependencies for cross-compiling to macOS.
# We use Zig as the linker to perform the compilation from a Linux host.
# Compilation is done via `cargo-zigbuild` which is a wrapper around `zig`.
RUN cargo install cargo-zigbuild@0.19.3


# Parts of the macOS SDK are required to build Radicle, we make these available
# here. So far only `CoreFoundation` and `Security` frameworks are needed.
RUN xz -d -c build/macos-sdk-11.3.tar.xz | tar -x
# This env var is used by `cargo-zigbuild` to find the SDK.
ENV SDKROOT /src/macos-sdk-11.3

# Build binaries.
RUN cargo zigbuild --locked --release \
    --target=x86_64-apple-darwin \
    --target=aarch64-apple-darwin \
    --target=aarch64-unknown-linux-musl \
    --target=x86_64-unknown-linux-musl \
    -p radicle-http-api

# Now copy the files to a new image without all the intermediary artifacts to
# save some space.
FROM alpine:3.20 as packager

ARG RADICLE_VERSION
ARG SOURCE_DATE_EPOCH

COPY --from=builder \
    /src/target/x86_64-unknown-linux-musl/release/radicle-http-api \
    /builds/x86_64-unknown-linux-musl/bin/
COPY --from=builder \
    /src/target/aarch64-unknown-linux-musl/release/radicle-http-api \
    /builds/aarch64-unknown-linux-musl/bin/
COPY --from=builder \
    /src/target/aarch64-apple-darwin/release/radicle-http-api \
    /builds/aarch64-apple-darwin/bin/
COPY --from=builder \
    /src/target/x86_64-apple-darwin/release/radicle-http-api \
    /builds/x86_64-apple-darwin/bin/
COPY --from=builder /src/*.1 /builds/x86_64-unknown-linux-musl/man/man1/
COPY --from=builder /src/*.1 /builds/aarch64-unknown-linux-musl/man/man1/
COPY --from=builder /src/*.1 /builds/aarch64-apple-darwin/man/man1/
COPY --from=builder /src/*.1 /builds/x86_64-apple-darwin/man/man1/

# Create and compress reproducible archive.
WORKDIR /builds
RUN apk update && apk add --no-cache tar xz
RUN find * -maxdepth 0 -type d -exec mv '{}' "radicle-http-api_$RADICLE_VERSION+{}" \; && \
    find * -maxdepth 0 -type d -exec tar \
    --sort=name \
    --verbose \
    --mtime="@$SOURCE_DATE_EPOCH" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    --format=posix \
    --pax-option=exthdr.name=%d/PaxHeaders/%f,delete=atime,delete=ctime \
    --mode='go+u,go-w' \
    --create --xz \
    --file="{}.tar.xz" \
    '{}' \;

FROM packager as signer

RUN apk add openssh

ARG RADICLE_VERSION
ARG RAD_PASSPHRASE
ARG RAD_PRIVATE_KEY

COPY --chmod=775 build/askpass build/sign build/askpass build/checksums build/version /usr/local/bin/
COPY build/TARGETS /opt/TARGETS

RUN /usr/local/bin/sign

FROM alpine:3.20
LABEL maintainer="Yorgos Saslis <yorgos.work@proton.me>"

RUN apk add git git-daemon

ARG RADICLE_VERSION
ENV PLATFORM=x86_64-unknown-linux-musl
ENV RADICLE_USER_ID=11011 RADICLE_GROUP_ID=11011
ENV BINARY_NAME="radicle-http-api_${RADICLE_VERSION}+${PLATFORM}"

# Copy over binaries
COPY --from=packager /builds /builds
WORKDIR /builds
RUN tar xf $BINARY_NAME.tar.xz

RUN mv $BINARY_NAME/bin/radicle-http-api /usr/local/bin/

RUN rm -rf $BINARY_NAME/

# Create a non-root user
RUN addgroup -S radicle -g $RADICLE_GROUP_ID  && adduser -S radicle -G radicle -u $RADICLE_USER_ID

# Change ownership of necessary directories/files
RUN chown -R radicle:radicle /home/radicle /usr/local/bin/radicle-http-api

USER radicle

WORKDIR /home/radicle

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/radicle-http-api"]
