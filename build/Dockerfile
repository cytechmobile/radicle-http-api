# Builds release binaries for Radicle.
FROM rust:1.81-alpine3.20 as builder
LABEL maintainer="Radicle Team <team@radicle.xyz>"
WORKDIR /src
COPY . .

# These arguments are necessary for the build to be reproducible.
ARG TZ
ARG LC_ALL
ARG SOURCE_DATE_EPOCH
ARG RADICLE_VERSION
ARG GIT_HEAD

