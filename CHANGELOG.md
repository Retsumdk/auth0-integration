# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-30

First tagged release. The package is consumed straight from GitHub until it reaches the npm registry.

### Added

- `Auth0Client` with `validateToken`, `getUser` and `getRoles`.
- Express middleware: `createAuthMiddleware`, `requireRole` and `requirePermission`.
- `getUserRoles` helper for reading roles from an access token.
- `Auth0Config`, `AuthUser` and `AuthRequest` types.
- `prepare` build step and a `files` allowlist, so `npm install github:Retsumdk/auth0-integration` yields a compiled package without a manual build.
- `CHANGELOG.md`.

### Fixed

- The `test` script could not run: the `jest` and `ts-jest` devDependencies and the ts-jest config were missing.
- `fetch` JSON responses were untyped, so `tsc` did not pass clean.

### Documentation

- The install section now documents the working GitHub install path instead of a registry name that is not published.
