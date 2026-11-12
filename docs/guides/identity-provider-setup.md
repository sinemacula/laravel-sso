# Setting Up an Identity Provider

A connection is registered twice: the tenant's administrator registers your service at their identity provider, and the
identity provider's side is entered into the connection. This guide gives the fields in generic terms first, then where
each one is at Microsoft Entra ID, Okta and Google Workspace. The step-by-step setup of each protocol is in
[Setting up a SAML connection](saml-connections.md) and [Setting up an OIDC connection](oidc-connections.md).

Providers rename their consoles' fields from time to time, and what a provider supports depends on its plan and on how
the tenant has configured it. The names below are the providers' own; confirm each against the provider's current
documentation, and test a connection end to end before you enable it. Where this guide is not sure a provider supports
something, it says what to check rather than claiming it does.

## What the identity provider is given

Everything here comes from the connection's service provider description
(`ServiceProviderDescriptions::describe()`, see [Service provider metadata](service-provider-metadata.md)), built from
`sso.endpoints.base_url` and the configured paths, never from a request. Each URL is compared exactly, so give it as
the description states it.

| Field                      | Protocol | Value                                                                                                    |
|----------------------------|----------|----------------------------------------------------------------------------------------------------------|
| Entity id, or audience     | SAML     | The connection's metadata URL, `.../auth/sso/connections/{connection}/metadata`                          |
| Assertion consumer service | SAML     | `.../auth/sso/connections/{connection}/assertions`, by HTTP-POST only                                    |
| NameID format              | SAML     | Persistent, unless the subject is an attribute (see [A stable subject](#a-stable-subject))               |
| Signing certificate        | SAML     | The service provider's signing certificate, when the connection signs its requests                       |
| Encryption certificate     | SAML     | The service provider's encryption certificate, when assertions are encrypted                             |
| Metadata URL               | SAML     | The same metadata URL, for a provider that fetches it rather than taking a file                          |
| Redirect URI, or callback  | OIDC     | `.../auth/sso/connections/{connection}/callback`, exactly                                                |
| Client authentication      | OIDC     | A client secret, or `private_key_jwt` with the JWKS at `.../auth/sso/connections/{connection}/jwks`      |
| Grant and scopes           | OIDC     | The authorisation code flow with PKCE (S256), scopes `openid`, `email` and `profile`                     |
| Start URL, or sign-on URL  | both     | Your application's own start page, only when the provider asks for one (a portal tile)                   |

A start URL is optional. A portal tile that posts an unsolicited SAML response is only ever re-initiated, and only on a
connection that allows it ([IdP-initiated sign-in](idp-initiated-sign-in.md)); a `RelayState` the provider sends is
ignored.

## What the connection is given

| Setting                                  | Protocol | Where it comes from                                                                                                              |
|------------------------------------------|----------|----------------------------------------------------------------------------------------------------------------------------------|
| `idp_entity_id`                          | SAML     | The provider's entity id, its `Issuer`, exactly as its metadata states it                                                        |
| `sso_url`, `sso_binding`                 | SAML     | The provider's single sign-on URL and its binding (HTTP-Redirect or HTTP-POST)                                                   |
| Trusted signing certificates             | SAML     | Each certificate the provider signs with, after comparing its fingerprint (see [Certificates](#certificates-and-their-rotation)) |
| `metadata_url`, and an anchor            | SAML     | The provider's metadata URL, to refresh from (see [SAML metadata](saml-metadata.md))                                             |
| `name_id_format`, or `subject_attribute` | SAML     | What the provider sends as the subject                                                                                           |
| `issuer`                                 | OIDC     | The issuer exactly as the provider's tokens carry it: case, trailing slash and path all count                                    |
| `client_id`, `client_secret`             | OIDC     | The client the administrator registered                                                                                          |
| Endpoints and algorithms                 | OIDC     | The discovery import, reviewed before it is saved (see [Import](oidc-connections.md#import))                                     |

A metadata file or discovery document only proposes these: nothing is trusted until an administrator saves it, with
fresh authentication.

## A stable subject

The subject is what a link is keyed by, with the connection and the issuer. A subject the provider ever gives to another
person signs that person in to the first one's account.

- **OIDC.** `sub` is the provider's identifier for the person. At some providers it is the same for every application
  and at others it is unique to the client registration; either is stable for one connection, but a new registration
  can mean new subjects. Changing the client or the issuer of a connection with links needs a
  [subject migration](managing-connections.md#migrating-subjects).
- **SAML.** Prefer a persistent `NameID`, or name an attribute that holds an identifier the provider never reuses, with
  `subject_source` `attribute`. An email or an unspecified `NameID` can be reassigned
  ([Opt-in features](opt-in-features.md#reassignable-nameid-formats)). Many providers default to an email-like value:
  change it at the provider before the first sign-in.

## Certificates and their rotation

- **Trust a certificate only after comparing its fingerprint** with one the provider's administrator gave you through
  another channel than the metadata itself. A certificate carried in a response is never trusted for itself.
- **The provider's certificate.** Trust the next certificate before the provider switches to it: both are trusted
  during the overlap. Distrust the old one once the provider has switched; distrusting voids flows in flight. With a
  metadata URL and a signing anchor (or the explicit `metadata_refresh` delegation), the scheduled refresh does this for
  you ([SAML metadata](saml-metadata.md#refreshing-on-a-schedule)). An OIDC provider's keys come from its JWKS, refetched
  on the schedule and when a token names a key the connection does not hold.
- **Your own keys.** Add the next key, give the provider the description with both certificates, and make it current
  only once the provider has the new one ([Keys and certificates](keys.md#generating-and-rotating-service-provider-keys)).
  A provider that took an uploaded file must be given it again at every rotation; one that fetches the metadata URL or
  the JWKS URL picks it up.
- **Client secrets expire** at some providers. Note the expiry, and update the connection's `client_secret` before it.

## Organisations that share an issuer

Some providers sign in every organisation they serve under one issuer (`https://accounts.google.com`), or under issuers
the package recognises as one provider's (Microsoft Entra ID's per-directory issuers). A link only ever resolves within
its own connection, so a person of another organisation never reaches a link of yours; but such a provider answers for
everyone it holds, so:

- **restrict the client to the organisation at the provider** wherever it allows that: a single-tenant registration at
  Microsoft Entra ID, an internal OAuth client in the organisation's own Google Cloud project;
- **check the organisation in your provisioning listener**, by mapping the organisation claim (`hd`, `tid`) to a
  custom attribute (`organization`, say) and refusing a result of another organisation: an unlinked result is offered
  for provisioning whoever it comes from;
- **name the organisation claim and value for linking by a verified domain**, which refuses a shared issuer without them
  ([Linking by a verified domain](linking-by-domain.md#classifying-the-issuer)).

## Microsoft Entra ID

### Over OpenID Connect (preset `microsoft_entra`)

| Generic field         | At Microsoft Entra ID                                                                                 |
|-----------------------|-------------------------------------------------------------------------------------------------------|
| Client registration   | App registrations, new registration, "Accounts in this organizational directory only" (single tenant) |
| Redirect URI          | Redirect URI of the Web platform: the callback                                                        |
| Client authentication | Certificates & secrets, a client secret, which expires                                                |
| Issuer                | `https://login.microsoftonline.com/{directory-id}/v2.0`, the directory's own, never `common`          |
| Organisation claim    | `tid`, the directory id                                                                               |

- Import from the directory's own issuer, so the connection holds the issuer its tokens carry. `common` and
  `organizations` are authorities, not issuers.
- Entra ID expects a client assertion to name its certificate by thumbprint (`x5t`). The package's client assertions
  name their key by `kid`, so use a client secret with Entra ID.
- An email is a linking email only with `email_verified` as boolean `true`. Check whether your directory's ID tokens
  carry it before you plan to link by a verified domain over OIDC; without it, link through the `link` purpose.

### Over SAML (preset `microsoft_entra_saml`)

| Generic field              | At Microsoft Entra ID                                                                                        |
|----------------------------|--------------------------------------------------------------------------------------------------------------|
| Registration               | Enterprise applications, a new application of your own, single sign-on by SAML                               |
| Entity id                  | Basic SAML Configuration, Identifier (Entity ID)                                                             |
| Assertion consumer service | Basic SAML Configuration, Reply URL (Assertion Consumer Service URL)                                         |
| Subject                    | Attributes & Claims, Unique User Identifier (Name ID): format Persistent, from an immutable source attribute |
| Provider's entity id       | `https://sts.windows.net/{directory-id}/`, shown as the Microsoft Entra Identifier                           |
| Provider's sign-on URL     | `https://login.microsoftonline.com/{directory-id}/saml2`, shown as the Login URL                             |
| Signing certificate        | SAML Certificates: the certificate (Base64) and its thumbprint                                               |
| Metadata URL               | SAML Certificates, App Federation Metadata Url                                                               |

- The default Name ID is the user principal name in an email format, which can be reassigned: change the Unique User
  Identifier before the first sign-in.
- Entra ID sends attributes with no `NameFormat`; name `urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified` for a
  linking attribute ([SAML attributes](linking-by-domain.md#saml-attributes)).
- If you turn on token encryption at Entra ID, check which content encryption it uses: anything other than AES-128-GCM
  or AES-192-GCM needs the [AES-CBC opt-in](opt-in-features.md#aes-cbc-compatibility), with its conditions.

## Okta

### Over OpenID Connect (preset `okta`)

| Generic field         | At Okta                                                                                                         |
|-----------------------|-----------------------------------------------------------------------------------------------------------------|
| Client registration   | Applications, create an app integration: OIDC - OpenID Connect, Web Application                                 |
| Redirect URI          | Sign-in redirect URIs: the callback                                                                             |
| Client authentication | Client authentication: a client secret, or a public key / private key                                           |
| Issuer                | The org authorisation server, `https://{okta-domain}`, or a custom one, `https://{okta-domain}/oauth2/{server}` |
| Groups                | A groups claim, which Okta sends only once it is configured                                                     |

- Use the issuer of the authorisation server your client's tokens come from; the two kinds are different issuers.
- For `private_key_jwt`, register the connection's public keys, by its JWKS URL where your organisation offers it, and
  check `token_endpoint_auth_signing_alg_values_supported` in the discovery document: if `PS256` is not listed, use a
  P-256 key or the `RS256` opt-in ([Client authentication](oidc-connections.md#client-authentication)).
- An Okta organisation is one organisation's issuer: for linking by a verified domain, classify it as
  `single_organization`, with the acknowledgement.

### Over SAML

| Generic field              | At Okta                                                                              |
|----------------------------|--------------------------------------------------------------------------------------|
| Registration               | Applications, create an app integration: SAML 2.0                                    |
| Assertion consumer service | Single sign-on URL, used for the Recipient and Destination URLs as well              |
| Entity id                  | Audience URI (SP Entity ID)                                                          |
| Subject                    | Name ID format and Application username                                              |
| Signatures                 | Response and Assertion Signature                                                     |
| Provider's details         | The app's Sign On tab: its metadata URL, issuer, sign-on URL and signing certificate |

- The Name ID's value is the application username, an Okta username (often an email) by default. Choose a Name ID
  format of Persistent only with a value Okta never reassigns, or send an immutable identifier as an attribute and use
  `subject_source` `attribute`.
- Keep the assertion signed. Sign the response as well if you need the AES-CBC opt-in.

## Google Workspace

### Over OpenID Connect (preset `google`)

| Generic field         | At Google                                                                                    |
|-----------------------|----------------------------------------------------------------------------------------------|
| Client registration   | Google Cloud console, the organisation's project: an OAuth client ID of type Web application |
| Restriction           | OAuth consent screen, user type Internal, so only the organisation's accounts can sign in    |
| Redirect URI          | Authorized redirect URIs: the callback                                                       |
| Client authentication | The client secret                                                                            |
| Issuer                | `https://accounts.google.com`, shared by every Google account                                |
| Organisation claim    | `hd`, the account's Workspace domain; absent for a consumer account                          |

- The preset fills in Google's issuer and endpoints; the administrator gives the client id and secret.
- Google documents `prompt` values `none`, `consent` and `select_account`. A `reauthenticate` sends `prompt=login` with
  `max_age=0`: test re-authentication against Google before you rely on it. A provider that does not report a fresh
  authentication is refused, so it fails closed.

### Over SAML

| Generic field              | At Google                                                                                                        |
|----------------------------|------------------------------------------------------------------------------------------------------------------|
| Registration               | Admin console, Apps, Web and mobile apps: add a custom SAML app                                                  |
| Provider's details         | Google Identity Provider details: SSO URL, Entity ID, the certificate and its fingerprint, and the metadata file |
| Assertion consumer service | Service provider details: ACS URL                                                                                |
| Entity id                  | Service provider details: Entity ID                                                                              |
| Subject                    | Name ID format and Name ID, a directory field                                                                    |
| Signatures                 | Signed response, which signs the whole response as well as the assertion                                         |

- Google offers its metadata as a file: import it with `MetadataImporter::importXml()`, or enter the entity id, the SSO
  URL and the certificate it shows, comparing the fingerprint.
- The Name ID is a directory field, typically the primary email, which can be reassigned. Treat it as reassignable
  unless you send an identifier you know is never reused.
- If the app offers no assertion encryption, leave `require_encrypted_assertions` off on the connection.

## Before you enable a connection

- Sign in through it once with a test account, and check that the subject is the value you expect.
- Re-authenticate through it if you use `reauthenticate`, and check that the session's time moves.
- If you accept provider evidence, check the `amr` or the context class the provider actually sends, and accept only
  values whose meaning at that provider you have confirmed ([Provider evidence](evidence.md)).
- Turn on enforcement for the tenant only after a sign-in through the connection has completed: the package refuses
  sooner ([Enforcement](enforcement.md)).
