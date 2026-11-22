# Changelog

## [0.2.0](https://github.com/sinemacula/laravel-sso/compare/v0.1.0...v0.2.0) (2026-11-22)


### Features

* accept aes-256-gcm encrypted saml assertions ([#125](https://github.com/sinemacula/laravel-sso/issues/125)) ([b956881](https://github.com/sinemacula/laravel-sso/commit/b95688148082ec3d20401e8d3fc5b2c33f9ec7ee))


### Bug Fixes

* allow guzzle 8 ([#123](https://github.com/sinemacula/laravel-sso/issues/123)) ([7226e38](https://github.com/sinemacula/laravel-sso/commit/7226e382c08dc7d79501f4e089c95b05bee8c4bf))
* verify saml signatures over nested default namespaces ([#124](https://github.com/sinemacula/laravel-sso/issues/124)) ([479f377](https://github.com/sinemacula/laravel-sso/commit/479f377f4764d2398d8da378f6a086ec2195eea2))

## 0.1.0 (2026-11-21)

First release. Tenant single sign-on for Laravel over SAML 2.0 and OpenID Connect: each tenant signs its people in
through its own identity provider, and the package hands the application a verified, single-use handoff to sign them in
with.

### Features

* SAML 2.0 and OpenID Connect drivers, including signed and encrypted SAML assertions
* tenant connections with settings, keys, metadata and administration events
* domain claims with verification, rechecks and enforcement
* discovery, authorisation requests, completion and single-use handoff codes
* linking, just-in-time provisioning, re-authentication and assurance evidence
* connection freshness and a policy version that changes with the connections that satisfy it
* pruning, scheduled checks and `sso:check`, which other packages can extend
* contract test kits for the seams a binder implements, and exported context keys and operation names
