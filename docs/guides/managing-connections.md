# Managing Connections

Your application's administration screens create and change a tenant's connections through
`SineMacula\Laravel\Sso\Connections\ConnectionService`, disable and delete them through
`SineMacula\Laravel\Sso\Connections\ConnectionLifecycle`, and move their links to a new identity provider or subject
through `SineMacula\Laravel\Sso\Connections\SubjectMigration`. Who may manage a tenant's connections is your
application's authorisation: check it before you call the services. Every call is scoped to a tenant, by the same
opaque string id your application uses (1 to 255 bytes), and a connection of another tenant is answered exactly as an
unknown one. The id is compared byte for byte, whatever your database's collation, so `acme` and `Acme` are two
tenants.

Resolve the services from the container for each request:

```php
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;

$connections = app(ConnectionService::class);
$lifecycle   = app(ConnectionLifecycle::class);
$migration   = app(SubjectMigration::class);
```

> [!IMPORTANT]
> Creating, changing a trust setting, enabling, disabling, deleting and migrating a connection each ask the freshness
> contract whether the caller authenticated recently enough, and the default contract refuses every operation. Bind
> your own first (see [Freshness](freshness.md)); until you do, every such call is refused with `freshness_required`.

## Creating a connection

A connection is created disabled, with its display name, its settings, its attribute mapping and, optionally, a preset
that fills in what is the same for every organisation using the provider:

```php
use SineMacula\Laravel\Sso\Administration\ActingIdentity;

$result = $connections->create(
    tenantId: $tenant->id,
    protocol: 'oidc',
    displayName: 'Acme Google Workspace',
    settings: [
        'client_id'     => '1234.apps.googleusercontent.com',
        'client_secret' => $request->input('client_secret'),
    ],
    preset: 'google',
    actor: new ActingIdentity($user->getMorphClass(), (string) $user->getKey()),
);

if ($result->isInvalid()) {
    return back()->withErrors(collect($result->violations)->mapWithKeys(fn ($violation) => [$violation->setting => $violation->code->value]));
}
```

What you give replaces what the preset fills in, setting by setting, and every check applies as it does to settings
entered by hand. A setting or mapping target given as `null` is not set. The connection may be saved incomplete: it is
never used until its settings are complete and it is enabled.

The acting identity is optional; when given, it is carried on the event the change reports.

## Updating a connection

`update()` takes the connection's id and the changes, under three keys:

```php
$result = $connections->update($tenant->id, $connectionId, [
    'display_name'      => 'Acme SSO',
    'settings'          => ['token_endpoint' => 'https://idp.acme.example/oauth2/token', 'userinfo_endpoint' => null],
    'attribute_mapping' => ['department' => 'dept', 'groups' => null],
], $actor);
```

- `settings`: a setting given replaces the stored one, and `null` removes it (a setting with a default returns to its
  default).
- A secret among the settings (an OIDC `client_secret`) given as a string sets it, and as `null` clears it. A secret
  you leave out is kept as it is stored, so an edit form never needs to send the secret back.
- `attribute_mapping`: a target given replaces the stored one, and `null` removes it.
- `display_name`: the new name.

The whole connection, as it would be stored, is validated again. A change to `tenant_id` or `protocol` is refused as
`immutable`, and any other key as `unknown`. An update that gives what is already stored succeeds as `unchanged`,
writes nothing and reports nothing; a map given again in another key order, such as `extra_parameters`, is what is
stored, while a list such as `scopes` is compared in order. Otherwise `changedSettings` names what changed: settings,
then secrets, then `display_name` and `attribute_mapping`.

Only a change to a setting that could widen or redirect access asks the freshness contract: the issuer or entity id,
the endpoints, the client id and secret, the subject settings and the algorithms ask `sso.connection.trust`;
IdP-initiated sign-in and its start URL ask `sso.connection.idp_initiated`; the scopes, extra parameters, request
options, display name and mapping ask nothing.

### Trust changes and sign-ins in progress

An update that asks `sso.connection.trust` also voids, in the same transaction, everything in flight through the
connection: every sign-in started but not yet finished, and every handoff code issued but not yet redeemed. Trusting or
distrusting an identity provider certificate does the same (see [Keys and certificates](keys.md)); rotating a key of
your own does not. See [what voiding does to people signing in](#what-voiding-does-to-people-signing-in).

### Settings that change what subjects mean

The OIDC `issuer` and `client_id`, and the SAML `idp_entity_id`, `subject_source`, `subject_attribute` and
`name_id_format`, decide what a subject the identity provider sends means. Changing one could make a person's link
point at someone else, so `update()` refuses it with `connection_has_links` while the connection has a link (active, or
reserved for a sign-in that has not expired). Freshness is asked first, so a stale caller is told `freshness_required`.
Make such a change with the [subject migration](#migrating-subjects) instead.

## Reading and listing connections

```php
$summary = $connections->get($tenant->id, $connectionId); // null when the tenant has no such connection
$all     = $connections->list($tenant->id);               // oldest first
```

Each is a `ConnectionSummary`: `id`, `tenantId`, `protocol`, `displayName`, `settings`, `secrets`,
`attributeMapping`, `enabled`, `hasCompletedSignIn`, `usable` (enabled, its protocol on and its settings complete)
and `createdAt` and `updatedAt` in UTC. A secret is never returned: `secrets` says only whether each is set. As JSON:

```json
{
    "id": "01jbz3k7m9q2w8e4r6t1y5u0ia",
    "tenant_id": "tenant-1",
    "protocol": "oidc",
    "display_name": "Acme Google Workspace",
    "settings": {"issuer": "https://accounts.google.com", "client_id": "1234.apps.googleusercontent.com"},
    "secrets": {"client_secret": {"set": true}},
    "attribute_mapping": {"email": "email", "groups": "groups"},
    "enabled": false,
    "has_completed_sign_in": false,
    "usable": false,
    "created_at": "2026-11-01T09:30:00Z",
    "updated_at": "2026-11-01T09:30:00Z"
}
```

## Enabling a connection

```php
$result = $connections->enable($tenant->id, $connectionId, $actor);
```

Enabling asks the freshness contract with `sso.connection.enable`, every time, then enables the connection and reports
it. Enabling an enabled connection succeeds as `unchanged`. A connection may be enabled before its settings are
complete; it is used only once they are.

## Disabling a connection

```php
$result = $lifecycle->disable($tenant->id, $connectionId, $actor);
```

Disabling asks the freshness contract with `sso.connection.enable`, every time, then, in one transaction: turns the
connection off, voids what is in flight through it, revokes every session established through it through the session
revocation contract (see [Revoking sessions](enforcement.md#revoking-sessions)), and reports `ConnectionDisabled`. Its
domains, links and keys are kept, so enabling it again restores it. Disabling a disabled connection succeeds as
`unchanged`, and writes, revokes and reports nothing.

## Deleting a connection

```php
$result = $lifecycle->delete($tenant->id, $connectionId, $actor);
```

Deleting asks the freshness contract with `sso.connection.delete`, then, in one transaction: withdraws what depends on
each of its verified domains, voids what is in flight, deletes the connection with its domains, links, keys, sign-ins in
progress and handoff codes, revokes every session established through it, and reports one `ConnectionDeleted` (no event
is reported for each link). It cannot be undone; the result is `deleted` and carries no summary.

A session revocation that throws rolls the disable or the deletion back, with nothing reported, and the exception
propagates. A connection whose protocol is no longer registered can still be disabled and deleted.

## Migrating subjects

When an organisation moves to another identity provider, or the provider changes how it identifies people, change the
settings and say, for each link you keep, what its subject is under the new meaning:

```php
$result = $migration->migrate($tenant->id, $connectionId, ['settings' => [
    'issuer' => 'https://login.acme.example',
]], [
    $linkId      => ['00u1a2b3c4'],                                 // the new subject
    $otherLinkId => ['E-1042', null, 'https://login.acme.example'], // the subject, no NameID format, the new issuer
], $actor);
```

Each relink is a list: the subject, then optionally the SAML NameID format and the issuer. A format left out or `null`
is none; an issuer left out or `null` is the link's own, so give the new issuer when the change moves to one. Every link
of the connection you do not list is removed, and its person's sessions through the connection are revoked; a person
whose link you relink keeps signing in. The change is validated as `update()` validates one, and each relink with it,
each problem at `relinks.<id>`: `unknown` for an id that is not one of this connection's links, `not_allowed` for a link
reserved for a sign-in in progress, `invalid_type` for a relink that is not such a list, `invalid_format` for an empty
or overlong part. It asks freshness for `sso.connection.trust` and `sso.link.remove` (and whatever else the change
asks), and voids what is in flight.

Everything happens in one transaction: if a new subject is already linked (two relinks to the same subject, say), the
result is `invalid` with `duplicate` at that relink, if a person would hold more links than the link limit allows, with
`too_many`, and nothing is changed. Once it commits, it reports `ConnectionUpdated`, a `LinkRemoved` for every link of
the connection, then a `LinkCreated` (origin `migration`) for each relink. A change that changes nothing succeeds as
`unchanged` and touches no link.

## What voiding does to people signing in

A disable, a deletion, a trust change and a migration each void what is in flight through the connection:

- someone who started signing in and has not come back from the identity provider, or whose response is being checked
  as the change commits, is sent back to your application with the failure `connection_unavailable` and starts again;
- a handoff code your application has not yet redeemed is refused as `handoff_unknown`, and the person signs in again
  for a new one;
- a code your application redeemed before the change is not affected: the person's session is handled by the session
  revocation contract instead (for a disable, a deletion or a removed link).

Schedule trust changes when few people are signing in, and tell your users that anyone mid-sign-in has to start over.

## Results

`create()`, `update()`, `enable()`, `disable()`, `delete()` and `migrate()` answer a `ConnectionResult`; a refusal is a
value, never an exception:

| `status`    | Predicates                     | Carries                                        |
|-------------|--------------------------------|------------------------------------------------|
| `created`   | `isSucceeded()`, `isChanged()` | `connection`                                   |
| `updated`   | `isSucceeded()`, `isChanged()` | `connection`, `changedSettings`                |
| `unchanged` | `isSucceeded()`                | `connection`                                   |
| `enabled`   | `isSucceeded()`, `isChanged()` | `connection`                                   |
| `disabled`  | `isSucceeded()`, `isChanged()` | `connection`                                   |
| `deleted`   | `isSucceeded()`, `isChanged()` | nothing                                        |
| `migrated`  | `isSucceeded()`, `isChanged()` | `connection`, `changedSettings`                |
| `refused`   | `isRefused()`                  | `reason`: see below                            |
| `invalid`   | `isInvalid()`                  | `reason`: `settings_invalid`, and `violations` |

A refused `reason` is `freshness_required`, `connection_not_found`, `protocol_unavailable` (not for a disable or a
deletion) or `connection_has_links` (an update only). A refused or invalid call writes nothing and reports nothing.
`protocol_unavailable` means no driver is registered under the protocol, or its switch in `sso.features` is off. An
empty or overlong tenant id is your application's mistake, an `InvalidArgumentException`; a database error or a secret
encrypter that cannot encrypt propagates.

Each violation names a setting by its dotted path (`issuer`, `signature_algorithms.2`, `extra_parameters.state`,
`attribute_mapping.email`, `display_name`, `preset`) and a code, never the value given:

| Code                    | Meaning                                                                                    |
|-------------------------|--------------------------------------------------------------------------------------------|
| `required`              | Empty, or needed by another setting (`subject_attribute`, `idp_initiated_start_url`)       |
| `invalid_type`          | The wrong type: a string where a list or a boolean was expected                            |
| `invalid_format`        | Malformed: not a URL, an entity id, a scope token, a name; a control character             |
| `not_https`             | A URL of another scheme than `https`                                                       |
| `too_long`              | Longer than its cap                                                                        |
| `too_many`              | More entries than its cap                                                                  |
| `not_allowed`           | Outside its allow-list: a binding, an algorithm, a parameter, a preset of another protocol |
| `reserved`              | A parameter the flow controls, a field of the result, a token, a secret among settings     |
| `unknown`               | A setting, change or preset the package does not have                                      |
| `duplicate`             | A list entry given twice                                                                   |
| `immutable`             | The tenant or the protocol                                                                 |
| `openid_scope_required` | The scopes leave out `openid`                                                              |
| `unsupported`           | Needs a feature switched on, or contradicts another setting                                |

## SAML settings

| Setting                        | Allowed                                                                       | Default              |
|--------------------------------|-------------------------------------------------------------------------------|----------------------|
| `idp_entity_id`                | An `https:`, `http:` or `urn:` URI, at most 1024 bytes, no whitespace         | none (required)      |
| `sso_url`                      | An `https` URL, no userinfo or fragment, at most 2048 bytes                   | none (required)      |
| `sso_binding`                  | `http_redirect`, `http_post`                                                  | `http_redirect`      |
| `subject_source`               | `name_id`, `attribute`                                                        | `name_id`            |
| `subject_attribute`            | An attribute name, at most 1024 bytes; only with `attribute`, and then needed | none                 |
| `name_id_format`               | `persistent`, `email`, `unspecified` (never `transient`)                      | `persistent`         |
| `sign_authn_requests`          | `true`, `false`                                                               | `false`              |
| `want_assertions_signed`       | `true`, `false`                                                               | `true`               |
| `require_encrypted_assertions` | `true` (with `sso.features.encrypted_assertions` on), `false`                 | `false`              |
| `signature_algorithms`         | RSA, RSA-PSS (`MGF1`) and ECDSA over SHA-256, SHA-384 or SHA-512; no SHA-1    | all nine             |
| `encryption_algorithms`        | RSA-OAEP key transport; AES-GCM, or AES-CBC when listed; never RSA 1.5        | RSA-OAEP and AES-GCM |
| `force_authn`                  | `true`, `false`                                                               | `false`              |
| `requested_authn_context`      | Up to 10 context class URIs, each at most 1024 bytes                          | none                 |
| `idp_initiated`                | `true` (with `sso.features.idp_initiated` on), `false`                        | `false`              |
| `idp_initiated_start_url`      | An `https` URL, as `sso_url`; needed when `idp_initiated` is on               | none                 |

The algorithms are given by their XML Signature and XML Encryption URIs, for example
`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` and `http://www.w3.org/2009/xmlenc11#aes256-gcm`; an encryption
list holds at least one key transport and one data algorithm. A SAML connection has no secret among its settings: its
key pairs and trusted certificates are managed with its keys (see [Keys and certificates](keys.md)).

## OIDC settings

| Setting                  | Allowed                                                                                                                                  | Default                      |
|--------------------------|------------------------------------------------------------------------------------------------------------------------------------------|------------------------------|
| `issuer`                 | An `https` URL, no query, userinfo or fragment, at most 2048 bytes; kept exactly as given                                                | none (required)              |
| `authorization_endpoint` | An `https` URL, no userinfo or fragment, at most 2048 bytes                                                                              | none (required)              |
| `token_endpoint`         | As `authorization_endpoint`                                                                                                              | none (required)              |
| `jwks_uri`               | As `authorization_endpoint`                                                                                                              | none (required)              |
| `userinfo_endpoint`      | As `authorization_endpoint`                                                                                                              | none                         |
| `returns_iss`            | `true`, `false`                                                                                                                          | `false`                      |
| `client_id`              | At most 255 bytes                                                                                                                        | none (required)              |
| `client_secret`          | A secret, at most 1024 bytes; not with `private_key_jwt`                                                                                 | none                         |
| `client_authentication`  | `client_secret_basic`, `client_secret_post`, `private_key_jwt`                                                                           | `client_secret_basic`        |
| `scopes`                 | Up to 20 distinct scope tokens, including `openid`                                                                                       | `openid`, `email`, `profile` |
| `id_token_algorithms`    | `RS256` to `RS512`, `PS256` to `PS512`, `ES256` to `ES512`; never `none` or `HS*`                                                        | `RS256`                      |
| `extra_parameters`       | Up to 10 of `prompt`, `acr_values`, `login_hint`, `ui_locales`, `claims_locales`, `display`, `domain_hint`, `hd`, each at most 512 bytes | none                         |

The issuer must be exactly the one your provider's ID tokens carry, trailing slash and case included. An extra
parameter the flow controls (`response_type`, `response_mode`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`,
`code_challenge`, `code_challenge_method`, `request`, `request_uri`) is refused as `reserved`, whatever its case.

## Attribute mapping

The mapping says which SAML attribute or OIDC claim each attribute of a sign-in's result is read from. The defaults:

| Target         | OIDC claim    | SAML attribute                      |
|----------------|---------------|-------------------------------------|
| `email`        | `email`       | `urn:oid:0.9.2342.19200300.100.1.3` |
| `given_name`   | `given_name`  | `urn:oid:2.5.4.42`                  |
| `family_name`  | `family_name` | `urn:oid:2.5.4.4`                   |
| `display_name` | `name`        | `urn:oid:2.16.840.1.113730.3.1.241` |
| `groups`       | `groups`      | `urn:oid:1.3.6.1.4.1.5923.1.5.1.1`  |

A preset's mapping replaces the defaults it names, and what you give replaces both. Besides the five standard targets,
you may add custom targets: lower-case names of a letter, then up to 63 letters, digits or underscores, at most
`sso.mapping.max_custom_attributes` of them (20 by default). A source is at most 1024 bytes.

A mapping can never target one of the result's own fields: `issuer`, `subject`, `name_id`, `name_id_format`,
`connection`, `connection_id`, `tenant`, `tenant_id`, `protocol`, `application`, `purpose`, `authentication_context`,
`auth_time`, `amr`, `acr`, `session`, `session_id`, `sid`, `session_index`, `email_verified`, `domain_verified`,
`identity`, `identity_id`, `reference` and `linking_email`. Over OIDC, a mapping can never read a protocol value or a
token: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`,
`c_hash`, `s_hash`, `sid`, `email_verified`, `access_token`, `id_token`, `refresh_token`, `code`, `state` and
`client_id`.

Mapped values are profile data, never what selects the identity a sign-in belongs to:

- each value is cut to `sso.mapping.max_value_length` characters (1024 by default);
- a list keeps at most `sso.mapping.max_values` strings (100 by default), in order, anything else dropped;
- `email`, `given_name`, `family_name` and `display_name` take one value, the first of a list;
- `groups` is always a list, passed on as the provider sent it, for your application or `laravel-authorization` to
  interpret.

| Key                             | Default | Range       | Env                                 |
|---------------------------------|---------|-------------|-------------------------------------|
| `mapping.max_value_length`      | `1024`  | 64 to 65535 | `SSO_MAPPING_MAX_VALUE_LENGTH`      |
| `mapping.max_values`            | `100`   | 1 to 10000  | `SSO_MAPPING_MAX_VALUES`            |
| `mapping.max_custom_attributes` | `20`    | 0 to 100    | `SSO_MAPPING_MAX_CUSTOM_ATTRIBUTES` |

A malformed cap fails closed, and the boot check and `php artisan sso:check` report it under `[mapping]`.
