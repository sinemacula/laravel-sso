# IdP-Initiated Sign-In

Some people start signing in from their identity provider rather than from your application: they open its portal
and click your application's tile. The identity provider then posts a SAML response nobody asked for, an *unsolicited*
response, to the connection's assertion consumer service. This guide is for whoever sets up such a connection and for
whoever builds the start route it sends the browser to.

The package supports IdP-initiated sign-in only by **re-initiation**. It never signs anyone in from an unsolicited
response: it checks the response in full, records it so it cannot be used again, and sends the browser to a start URL
in your application, which starts an ordinary SP-initiated sign-in through the connection. The identity provider
answers that from the session the person already has there, usually without asking anything, so to the person it is
one click.

## Why not sign in directly

An unsolicited assertion is bound to no request and no browser, so whoever posts it is believed. Two attacks follow:

- **Login CSRF.** An attacker signs in at the identity provider as themselves, keeps the assertion, and makes your
  user's browser post it (a hidden form on any page will do). Your user is now signed in to the attacker's account,
  and what they type or upload is the attacker's to read.
- **An intercepted assertion.** An assertion that leaks (through a log, a proxy, the browser's history or a shared
  machine) can be posted by anyone until it expires. Recording assertions against replay stops a second use, not the
  first one.

Re-initiation answers both: the sign-in that actually happens is SP-initiated, so it is tied to an authorisation request
your API stored, to its `RelayState`, and to the browser and client that started it. A posted assertion of someone else
only ever leads your user's browser to your own start page.

## Turning it on

IdP-initiated sign-in is off by default, for the application and for every connection.

1. Enable the feature: `sso.features.idp_initiated` (`SSO_IDP_INITIATED`), which needs `sso.features.saml2`.
2. On each connection that should accept it, set `idp_initiated` to `true` and `idp_initiated_start_url` to the start
   URL in your application: an `https` URL, without user information or a fragment. It may carry a query of its own.

Both settings ask the freshness contract for `sso.connection.idp_initiated`, so changing them needs a recent
authentication. Turning the feature off again makes every connection that still has `idp_initiated` on incomplete: it
refuses every sign-in until the setting is turned off on the connection, so turn it off there first.

Tell the identity provider to send its unsolicited responses to the connection's assertion consumer service URL, the
same URL as for SP-initiated sign-in, and to send them signed exactly as it signs its other responses.

## What the package checks

An unsolicited response is held to every rule a solicited one is: every signature verified with a certificate the
connection trusts, the signature wrapping defences, the issuer, the `Destination`, encryption when the connection
requires it, the conditions and every audience, one bearer confirmation whose `Recipient` is the assertion consumer
service, the subject (a transient `NameID` is never accepted) and the authentication context. See
[Signing In with SAML](saml-sign-in.md).

A response is unsolicited only when no `InResponseTo` appears anywhere in it: not on the response, not on a bearer
confirmation and not inside an encrypted assertion. A response whose `InResponseTo` names a request your API started is
completed as that request, as usual; one that names a request the API does not know is refused with `request_unknown`,
never treated as unsolicited.

Once the response passes, the connection is checked again under its lock: it must still be enabled and complete, and
nothing that changes whom it trusts (distrusting a certificate, changing a metadata signing anchor, disabling it) may
have happened while the response was checked. Then the assertion is recorded against replay, until the last moment it
could still be accepted. Only then is the browser sent on.

## The start URL contract

A re-initiated completion answers `CompletionResult::reinitiated()`, which your completion controller turns into a
`303` to the start URL as for any other outcome (see [Completion Responses](completion-responses.md)). The URL is
exactly the one you set, with one query parameter added: `connection`, the connection's id. It is added after a `?`
when the URL has no query and after an `&` when it has one:

| `idp_initiated_start_url`                   | Where the browser goes                                       |
|---------------------------------------------|--------------------------------------------------------------|
| `https://app.example.com/sso/start`         | `https://app.example.com/sso/start?connection=01j…`          |
| `https://app.example.com/sso/start?via=idp` | `https://app.example.com/sso/start?via=idp&connection=01j…`  |

The `RelayState` the identity provider posts is never read, so it can never choose where the browser goes. If your
identity provider puts a deep link there, it is ignored.

The start URL belongs to your client application (a web front end, say), not to the API. It must start an SP-initiated
flow; it must not treat the request as signed in:

1. Read `connection` from the query. Treat it as untrusted input: it only says which connection to try.
2. Start a `sign_in` through that connection as your client always does (see [Starting a Flow](starting-a-flow.md)),
   with your client's own application name and its own PKCE challenge.
3. Navigate to the identity provider as the start answers. The identity provider recognises the person's session and
   sends back a solicited response, which completes as any other sign-in.

Nothing of the unsolicited response carries into that flow: its subject, attributes and authentication context were
only checked, never kept. A person whose identity provider session has ended in between is simply asked to sign in
there again.

## Failures and events

Every refusal of an unsolicited response is `rejected`: a `400` with no redirect, since such a response names no
application whose redirect URI could be trusted.

| Reason                    | Why                                                                                         |
|---------------------------|---------------------------------------------------------------------------------------------|
| `unsolicited_not_allowed` | The connection does not allow IdP-initiated sign-in                                         |
| `connection_unavailable`  | The connection is disabled, incomplete, or its trust changed while the response was checked |
| `metadata_expired`        | The identity provider metadata the connection refreshes from has expired                    |
| `request_unknown`         | The response carries an `InResponseTo` naming no request your API started                   |
| `replayed`                | The assertion was posted before                                                             |

Any other reason is the same as for a solicited response (`signature_invalid`, `audience_mismatch`,
`assertion_expired` and the rest), listed in [Events](events.md).

A re-initiation dispatches `UnsolicitedResponseReinitiated` once the assertion is recorded; a refusal dispatches one
`FlowFailed` for the `assertion` flow. Each names the connection, its tenant and its protocol only: no request
reference, no application and no identity, since nobody was signed in. No event or log ever holds the response, the
assertion, the `RelayState`, the `NameID` or an attribute's value. A response refused because the connection does not
allow IdP-initiated sign-in is also logged as a notice naming the connection, so you can tell when an identity provider
sends responses nobody enabled.
