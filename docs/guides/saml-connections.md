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

### SAML is RSA only

SAML keys and certificates are RSA, for every use. On PHP 8.3 the package uses saml2 v6, which signs, verifies and
decrypts with RSA alone, so it accepts:

- signatures by RSA with SHA-256, SHA-384 or SHA-512 (`signature_algorithms`);
- key transport by RSA-OAEP, and content encryption by AES-128-GCM or AES-192-GCM, or AES-CBC when you list it
  (`encryption_algorithms`).

Anything else is refused when it is configured, never at sign-in: generating an elliptic curve key for `SP_SIGNING` or
`SP_ENCRYPTION` is invalid (`key_type`, `not_allowed`); trusting an elliptic curve certificate as an identity provider
signing certificate or a metadata signing anchor is invalid (`certificate`, `unsupported`); and listing ECDSA, RSA-PSS
or AES-256-GCM in a connection's algorithms is invalid (`not_allowed`). An identity provider that signs only with ECDSA,
or encrypts only with AES-256-GCM, cannot be connected over SAML yet: ECDSA and AES-256-GCM arrive when the package's
PHP floor moves to 8.5 and saml2 v7 is stable. Most identity providers sign with RSA by default; ask its administrator
for an RSA signing certificate.

## 4. Trust the identity provider

Trust each signing certificate the identity provider publishes, after comparing its fingerprint with the one its
administrator gave you (see [Keys](keys.md#trusting-identity-provider-certificates)):

```php
$keys->trustCertificate($tenant->id, $connectionId, $certificatePem, $actor);
```

A signature is valid when any trusted certificate verifies it; a certificate carried in a response is never trusted for
itself. To keep the certificates and the sign-on endpoint up to date from the identity provider's metadata, save its
`metadata_url`, run the refresh command, and optionally trust a metadata signing anchor (see
[SAML metadata](saml-metadata.md#refreshing-on-a-schedule)).

### Large federation metadata

A federation (InCommon, eduGAIN, a national research network) may publish one signed aggregate of every member, tens
of MiB. The package reads it out of the box, but the cap is 1 MiB by default (`sso.metadata.max_bytes`, up to 256 MiB),
in place of the fetcher's own cap, which every other request keeps:

```dotenv
SSO_METADATA_MAX_BYTES=67108864
SSO_FETCHER_TIMEOUT_SECONDS=60
SSO_METADATA_QUEUE_CONNECTION=redis
SSO_METADATA_QUEUE=metadata
SSO_METADATA_QUEUE_TIMEOUT_SECONDS=600
SSO_METADATA_CLAIM_SECONDS=900
REDIS_QUEUE_RETRY_AFTER=660
```

> **Raising the cap has a cost.** The whole file is downloaded, held in memory, parsed and its signature checked in one
> piece, every time it is imported or refreshed: expect memory of several times the file's size and seconds of
> processing for an aggregate of tens of MiB. Size each limit on the way for it:
>
> - the download: `SSO_FETCHER_TIMEOUT_SECONDS` bounds every fetch from connecting to the last byte, 10 seconds by
>   default and at most 60. It is shared by every outbound request (token, UserInfo, discovery, JWKS), so raising it
>   raises their deadline too. A file of 64 MiB needs a sustained 54 Mbit/s to arrive in 10 seconds, and 9 Mbit/s in
>   60; one that cannot arrive in 60 seconds fails every time (`fetch_failed`), so use a per-entity URL instead;
> - the job: `SSO_METADATA_QUEUE_TIMEOUT_SECONDS`, at most `SSO_METADATA_CLAIM_SECONDS`;
> - the queue connection's `retry_after` (90 seconds in Laravel's stock `config/queue.php`), longer than the job's
>   timeout, or a refresh still running is reserved by a second worker and recorded as a failed job; the boot check
>   refuses a timeout that is not shorter;
> - the worker's `--timeout` and `--memory`.
>
> Import such a URL from the console or a queued job, never a web request, since an import fetches while it is called.
> Where the federation publishes a URL per entity (an MDQ service, say), use that instead: it is a few KiB.

The aggregate's own signature is verified with the anchor you trust, and exactly one entity with the pinned entity id
is chosen from it. Only that entity is checked against the metadata schema: another member holding a value the schema
or the SAML library refuses (a relative logo, an organisation URL with no scheme) never stops your connection reading
its own (see [SAML metadata](saml-metadata.md#large-federation-metadata)).

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
