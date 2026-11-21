# Changelog

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
