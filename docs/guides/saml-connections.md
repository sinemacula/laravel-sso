# Setting Up a SAML Connection

This guide walks through setting up one organisation's SAML 2.0 connection from start to finish: switching SAML on,
creating the connection, giving it its keys, trusting the identity provider, registering your service at the identity
provider, and enabling it. Each step links to the guide that describes it in full. What the package then holds every
response to is in [Signing in with SAML](saml-sign-in.md).

## 1. Switch SAML on

SAML is off until you switch it on, with the features the organisation's identity provider needs:

```dotenv
SSO_SAML2=true
# Only when a connection requires encrypted assertions
SSO_ENCRYPTED_ASSERTIONS=true
# Only when a connection refreshes its identity provider's metadata on a schedule
SSO_METADATA_REFRESH=true
# Only when a connection allows sign-in started at the identity provider
SSO_IDP_INITIATED=true
```

Set `sso.endpoints.base_url` too: every connection's entity id, assertion consumer service and metadata URL are built
from it and the configured paths, never from a request (see [Configuration](configuration.md#endpoints)). Then run
`php artisan sso:check`, which names anything SAML still needs. The installation guide lists what the SAML library
needs of Composer and its limits (see [Installation](installation.md)).

## 2. Create the connection

Create it with the identity provider's entity id and single sign-on URL, from the organisation's administrator or from
its metadata (see [SAML metadata](saml-metadata.md#importing-metadata), which proposes these settings and the
certificates without trusting anything):

```php
use SineMacula\Laravel\Sso\Connections\ConnectionService;

$result = app(ConnectionService::class)->create(
    tenantId: $tenant->id,
    protocol: 'saml2',
    displayName: 'Acme Entra ID',
    settings: [
        'idp_entity_id'  => 'https://sts.windows.net/0000-1111/',
        'sso_url'        => 'https://login.microsoftonline.com/0000-1111/saml2',
        'sso_binding'    => 'http_redirect',
        'name_id_format' => 'persistent',
    ],
    actor: $actor,
);
```

A connection is created disabled and may be saved incomplete. Every SAML setting, what it allows and its default are in
[Managing connections](managing-connections.md#saml-settings). Choose the subject with care: a persistent `NameID`, or
an attribute holding an identifier the identity provider never reuses (see
[Signing in with SAML](saml-sign-in.md#the-subject)).

## 3. Give it its keys

The package generates the service provider's key pairs; their certificates are published in the connection's
metadata (see [Keys](keys.md#generating-and-rotating-service-provider-keys)):

- a signing key (`KeyUse::SP_SIGNING`), needed when the connection signs its `AuthnRequest`s
  (`sign_authn_requests`);
- an encryption key (`KeyUse::SP_ENCRYPTION`), needed when the connection requires encrypted assertions
  (`require_encrypted_assertions`), and used whenever the identity provider encrypts one.

```php
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyService;

$keys = app(KeyService::class);

$keys->addNext($tenant->id, $connectionId, KeyUse::SP_SIGNING, actor: $actor);
$keys->addNext($tenant->id, $connectionId, KeyUse::SP_ENCRYPTION, actor: $actor);
```

SAML keys are RSA: the SAML library the package uses signs and decrypts with RSA alone.

## 4. Trust the identity provider

Trust each signing certificate the identity provider publishes, after comparing its fingerprint with the one its
administrator gave you (see [Keys](keys.md#trusting-identity-provider-certificates)):

```php
$keys->trustCertificate($tenant->id, $connectionId, $certificatePem, $actor);
```

A signature is valid when any trusted certificate verifies it; a certificate carried in a response is never trusted for
itself. To keep the certificates and the sign-on endpoint up to date from the identity provider's metadata, save its
`metadata_url`, switch `metadata_refresh` on, and optionally trust a metadata signing anchor (see
[SAML metadata](saml-metadata.md#refreshing-on-a-schedule)).

## 5. Register your service at the identity provider

Give the identity provider your service provider metadata: the entity id, the assertion consumer service (HTTP-POST),
the published certificates, the NameID format, and whether requests are signed and assertions must be. Serve it from a
route of your own, or hand the administrator the file (see [Service provider metadata](service-provider-metadata.md)).

Register the assertion consumer service and the start route your application already serves (see
[Starting a flow](starting-a-flow.md) and [Completing a flow](completing-a-flow.md)). Responses are accepted there by
HTTP-POST only.

## 6. Enable it

```php
$result = app(ConnectionService::class)->enable($tenant->id, $connectionId, $actor);
```

Enabling does not check that the connection is complete, but an incomplete one is never used: a SAML connection is
usable only while its settings are complete, it trusts at least one signing certificate, and it has each current key
its settings need. `ConnectionService::get()` shows whether it is. Once it is usable, sign-in through it starts with
`AuthorizationRequestService::start()` and completes at the assertion consumer service.

## Optional: sign-in started at the identity provider

To let people start from the identity provider's portal, switch `idp_initiated` on with the start URL your application
serves. The package never signs anyone in from an unsolicited response: it checks it in full, records it, and sends the
browser to that start URL, which starts an ordinary sign-in (see [IdP-initiated sign-in](idp-initiated-sign-in.md)).

## Changing it later

Every change that could widen, redirect or destroy access (a trust change, a key rotation, a disable) asks the
freshness contract first (see [Freshness](freshness.md)), and a trust change voids the flows in flight through the
connection (see [Managing connections](managing-connections.md)). Rotate keys and certificates without downtime as
[Keys](keys.md) describes, and plan a change of subject settings on a connection with links through the subject
migration helper.
