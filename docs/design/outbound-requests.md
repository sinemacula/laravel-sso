# Outbound Requests

## Purpose

This note records how the package makes a request to an address it does not control: an identity provider's metadata,
discovery document, JWKS, token endpoint or UserInfo endpoint, each an address an administrator entered or that
metadata or discovery supplied. Every such request goes through one fetcher, so a URL that points inside the
application's network (server-side request forgery), a host that resolves one way when checked and another when
connected to (DNS rebinding), a redirect that leads somewhere private, a response that never ends and a credential sent
where it does not belong are refused in one place (SSO-2.9, the OWASP Server-Side Request Forgery Prevention Cheat
Sheet).

## Invariants

- There is one fetcher: `Contracts\Fetcher::fetch(FetchRequest): FetchResult`. A request is built only through the
  named constructor of its purpose (`metadata`, `discovery`, `jwks`, `token`, `userInfo`), which pairs it with the only
  credential that purpose may carry. The default is `Fetching\GuzzleFetcher`, bound with `scopedIf`, so nothing of one
  request or job outlives it under Octane or a queue worker (SSO-11.2).
- Every URL, the request's own and each redirect's, is checked the same way before anything is resolved or sent:
  - the scheme, compared without regard to case, is `https`; anything else is refused (`scheme`);
  - it carries no userinfo (`user@`, `user:pass@`, an empty `@`), so `https://idp.example.com@169.254.169.254/` cannot
    be read as the identity provider by one parser and the metadata address by another (`userinfo`);
  - it has a host, no fragment, a port from 1 to 65535, and no control character, space, DEL or backslash, so nothing
    in it can be read two ways (`malformed`);
  - its host is normalised: lower case, IDNA to ASCII with `idn_to_ascii()` (UTS 46, nontransitional), one trailing
    dot stripped; a host that cannot be converted, or that is not then dot-separated labels of letters, digits,
    hyphens and underscores (a percent-escape, an empty label, more than 253 characters), is refused (`malformed`).
    A URL holding a byte over 0x7F has its host converted before the URL is parsed, since `parse_url()` rewrites
    some such bytes, and every such byte after the host percent-encoded. A host that converts to a delimiter (a
    full-width `:`, `@` or `/` becomes the ASCII one) is refused rather than read again with the delimiter in it
    (`malformed`);
  - an IP literal must be canonical: a bracketed IPv6 address exactly as `inet_ntop()` writes it, or a dotted quad.
    A host made only of digits, dots and `x`, or whose last label is a decimal, octal or hex number, that is not a
    canonical dotted quad is refused (`ip_form`), which defeats `2130706433`, `0177.0.0.1`, `017700000001`, `0x7f.1`,
    `0x7f000001`, `127.1`, `127.0.1`, `127.0.0.01`, `[0:0:0:0:0:0:0:1]`, `[::ffff:7f00:1]` and a zone id: forms a
    resolver or `inet_aton()` reads as a loopback or metadata address that a string comparison would miss. A host in
    full-width digits is converted to ASCII first, so it is judged as the dotted quad it becomes.
- A host name is resolved once, through `Contracts\HostResolver` (`SystemHostResolver` by default, `dns_get_record()`
  for A and AAAA records). No address fails the request (`unresolved`). If any address it resolves to is refused, the
  request is refused (`refused_address`): a split answer of one public and one private address, or one that rotates
  between them, cannot slip through by the order it is tried in. An IP literal is checked directly and never resolved.
- `Fetching\AddressPolicy::isRefused()` judges an address on its `inet_pton()` bytes, so how it is written cannot move
  it out of a range. It refuses anything that is not a valid IP literal, and:
  - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16` (link-local, and the cloud
    metadata address `169.254.169.254`), `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.88.99.0/24`,
    `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4` and
    `255.255.255.255/32`;
  - IPv6: `::/128`, `::1/128`, `100::/64`, `2001::/32` (Teredo, refused whole since the IPv4 address it carries is
    obfuscated), `2001:db8::/32`, `fc00::/7` (unique-local, with AWS's `fd00:ec2::254`), `fe80::/10`, `fec0::/10` and
    `ff00::/8`;
  - an IPv6 address that carries an IPv4 address is judged by that address as well: mapped (`::ffff:0:0/96`),
    compatible (`::/96`), translated (`::ffff:0:0:0/96`), NAT64 (`64:ff9b::/96`, and `64:ff9b:1::/48` with the RFC
    6052 `/48` layout) and 6to4 (`2002::/16`), so `::ffff:127.0.0.1`, `::127.0.0.1`, `64:ff9b::a9fe:a9fe` and
    `2002:7f00:1::` are refused with the IPv4 ranges they reach, and a public address so carried is allowed;
  - every range in `sso.fetcher.refused_ranges`, which adds to the built-in ranges and never removes one. A configured
    IPv4 range also applies to an IPv4 address carried in IPv6.
- The connection is pinned to the first checked address with `CURLOPT_RESOLVE` (`host:port:address`, an IPv6 address
  in brackets, the port 443 unless the URL names one), so cURL never resolves the name a second time and DNS rebinding
  cannot change where it connects. The request keeps the host name, so the certificate and host name are verified
  against the name, never the address: pinning removes the second lookup without weakening TLS.
- The transport is fixed, with no setting to loosen it: `verify` true, `allow_redirects` false (and cURL never follows
  one), `http_errors` false, `cookies` false, `proxy` `''` (so neither an explicit nor an environment proxy, such as
  `HTTPS_PROXY`, is used), `decode_content` false with no `Accept-Encoding` sent (so the size cap is on the bytes
  received, not on a decompressed body), `https` as the only protocol, `User-Agent: laravel-sso`, and `Accept` by
  purpose (metadata `application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8`; JWKS
  `application/jwk-set+json, application/json;q=0.9`; the rest `application/json`). On Guzzle 7 the fetcher also sets
  `CURLOPT_PROTOCOLS` and `CURLOPT_REDIR_PROTOCOLS` to `CURLPROTO_HTTPS`, `CURLOPT_FOLLOWLOCATION` false and
  `CURLOPT_NOPROXY` `*`; Guzzle 8 sets the same from the `protocols`, `allow_redirects` and `proxy` options and
  refuses them in the `curl` option, so there the fetcher leaves them to it.
  The package requires Guzzle `^7.9` for now, because the SAML library holds it there (`saml-library.md`); the
  Guzzle 8 handling stays, so moving up is a change of constraint only.
- The handler is Guzzle's `CurlHandler`, built by the fetcher, never `choose_handler()`, the stream handler or a proxy
  handler, because only cURL can pin the address with `CURLOPT_RESOLVE`. Without `ext-curl` and with no handler
  injected, the constructor throws a `LogicException` rather than fall back. `[fetcher]` reports a missing `ext-curl`
  or cURL handler at boot.
- Caps: the request may take `timeout_seconds` (1 to 60, default 10) and connecting `connect_timeout_seconds` (1 to
  30, default 5, at most the timeout), each per hop. The response may be at most `max_response_bytes` (1024 to 10485760,
  default 1048576): a declared `Content-Length` over it aborts the transfer from `on_headers`; the body is written
  into a `Fetching\CappedSink`, which refuses the write that would pass the cap, so cURL aborts the transfer there
  with a write error on Guzzle 7 and 8 alike; and the body is read back no further than a byte past the cap and
  measured again. The `progress` callback also aborts once the bytes received pass the cap, on a Guzzle that acts on
  its answer. Over the cap fails (`too_large`); a body without a declared length is never held past the cap.
- Redirects: a request for a credentialed purpose (`token`, `userinfo`) follows none; a redirect answer is refused
  (`redirect_refused`) and its `Location` is never resolved or asked, so the credential is never sent on. Any other
  request follows a `3xx` with a `Location` at most `max_redirects` times (0 to 10, default 3), the `Location`
  resolved against the URL that answered it, each hop checked, resolved, checked against the policy and pinned again,
  with `GET`, the purpose's headers and nothing else. A redirect to a refused scheme, host or address is refused; one
  past the limit fails (`too_many_redirects`). A `3xx` without a `Location` is a response like any other.
- Credentials, exactly one, by kind (`FetchCredentials`), and nothing else ever sent (no cookie, no other header):
  - `client_secret_basic`: `Authorization: Basic base64(urlencode(client_id) ":" urlencode(secret))` (RFC 6749
    §2.3.1), so a colon or non-ASCII character in either cannot be misread;
  - `client_secret_post`: `client_id` and `client_secret` in the form;
  - `private_key_jwt`: `client_id`, `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
    and `client_assertion` in the form (RFC 7523 §2.2);
  - `access_token`: `Authorization: Bearer <token>` (RFC 6750 §2.1), for UserInfo only.

  A token request is a `POST` whose body is `http_build_query(form + credential fields, '', '&', PHP_QUERY_RFC1738)`
  as `application/x-www-form-urlencoded`; its form cannot set a client authentication field of its own
  (`FetchRequest::RESERVED_FORM_FIELDS`), so exactly one client authentication is sent. Metadata, discovery and JWKS
  requests are a bare `GET` with no credential and no body.
- Outcomes (see `outcomes.md`): any HTTP status received within the caps is `fetched`, with the status, each header's
  first value and the body (whether a `400` from a token endpoint is an error is the caller's to read). A refusal
  before sending is `FetchResult::refused()` (`fetch_refused`); a failure once resolution or sending began (no address,
  a transport or TLS error, `ConnectException`, `RequestException` or any `TransferException`, too large, too many
  redirects, or a request Guzzle or PSR-7 refuses to build, such as a header value it rejects) is
  `FetchResult::failed()` (`fetch_failed`). Neither carries anything but its reason code. A malformed setting throws
  `InvalidArgumentException`, a server error, before anything is sent. An access token that is not an RFC 6750
  b64token is refused when its `FetchCredentials` is built, so it can never put a control character into a header.
- Each refusal and failure is logged once, as a warning: `sso.fetch.refused` or `sso.fetch.failed`, with `purpose`,
  `reason` (the code), `cause` (`scheme`, `userinfo`, `malformed`, `ip_form`, `refused_address`, `unresolved`,
  `redirect_refused`, `too_many_redirects`, `too_large` or `transfer`), `host` (the normalised host, when there is one)
  and `exception_class`. Never the URL's path or query, the form, a credential, a header, the body or the exception's
  message, which can quote the URL. A success logs nothing.
- Settings are read on each call through `Fetching\FetcherSettings`, with `Config\IntegerSetting` for the integers. A
  malformed value fails closed with an `InvalidArgumentException` naming its key (`sso.fetcher.refused_ranges.<index>`
  for one range), never its value. `[fetcher]` (`Fetching\FetcherCheck`) applies while the package is in use, reports
  each setting on its own, a connect timeout past the timeout, and a missing cURL transport.
- An application may bind its own `Contracts\Fetcher` (to send through an egress proxy that enforces its own
  allow-list, say) in a service provider; one bound before the package registers is kept, one bound after replaces the
  default. It takes on every obligation of the contract: `https` only with certificate and host name verification;
  refusing the same addresses, IPv6 forms included, and the configured ranges (`AddressPolicy` can be reused for that);
  connecting to the address it checked, or leaving resolution and the check to a proxy that does both; no redirect for
  a credentialed request and a checked one otherwise; the size and time caps; the request's one credential as its kind
  says and nothing else; refusals and failures as `FetchResult::refused()` and `FetchResult::failed()`, never an
  exception; and nothing of the request's form, credential or the response's body in a log, an exception or an event.
  An application that keeps the default fetcher but needs another resolver (a bounded deadline, DNSSEC, DNS over
  HTTPS) binds `Contracts\HostResolver` instead, which the default fetcher resolves from the container. The default,
  `Fetching\SystemHostResolver`, is bound there as a singleton, since it holds nothing between calls.

## Success Path

1. A flow builds the request for its purpose (`FetchRequest::metadata($url)`,
   `FetchRequest::token($url, $form, FetchCredentials::clientSecretBasic($id, $secret))`) and resolves
   `Contracts\Fetcher` from the container.
2. The fetcher checks and normalises the URL, resolves the host once, checks every address, and pins the first.
3. It sends through Guzzle on the cURL handler with the fixed options, the time caps, the size cap and the request's
   one credential.
4. A `3xx` with a `Location` on an uncredentialed request is followed: steps 2 and 3 again for the resolved `Location`,
   with `GET`, up to the limit.
5. The response is answered as `FetchResult::fetched($status, $headers, $body)`; the caller reads the status and body.

## Failure / Edge Cases

- `http:`, `file:`, `gopher:` and a URL with no scheme are refused before any lookup. So is a redirect to one.
- `https://idp.example.com#@evil.example/`, `https://idp.example.com\@evil.example/` and a URL with a space, tab,
  newline or null byte are refused, so a parser that splits the URL another way never sees it.
- A host resolving to `93.184.216.34` and `10.0.0.5`, in either order, is refused; so is one resolving to a garbage
  string, which the policy refuses as not an IP literal.
- A host with no addresses, or whose lookup warns or fails, fails as `unresolved`. The system resolver has no timeout
  of its own; bind your own `HostResolver` for a bounded one.
- An internationalised host is resolved, pinned and sent as its ASCII form (`bücher.example` as
  `xn--bcher-kva.example`); `idp.example.com.` as `idp.example.com`.
- The time caps apply per hop, so a request that follows every redirect it may can take up to `max_redirects + 1`
  timeouts in all.
- Guzzle 7 ignores `progress`'s return value, so there the sink alone stops a body without a declared length: its
  refused write aborts the transfer as soon as the cap is passed, on both Guzzle 7 and 8.
- cURL may reuse a connection for a later request to the same host and port within the same scoped fetcher; that
  connection is to an address that was checked when it was opened.
- A configured range with host bits set (`10.1.2.3/8`) refuses the whole range its prefix names.
- `FetcherCheck` reports a malformed timeout once, not again as a connect timeout past it.

## Implementation Anchors

- `src/Contracts/Fetcher.php`.
- `src/Fetching/FetchRequest.php`, `src/Fetching/FetchCredentials.php`, `src/Fetching/FetchResult.php`,
  `src/Fetching/Enums/FetchPurpose.php`, `src/Fetching/Enums/CredentialKind.php`, `src/Fetching/Enums/FetchStatus.php`.
- `src/Fetching/GuzzleFetcher.php`, `src/Fetching/CappedSink.php`, `src/Fetching/AddressPolicy.php`,
  `src/Fetching/FetcherSettings.php`, `src/Contracts/HostResolver.php`, `src/Fetching/SystemHostResolver.php`,
  `src/Fetching/FetcherCheck.php`.
- `src/Testing/FakeFetcher.php`.
- `src/SsoServiceProvider.php`: `register()` (`scopedIf(Fetcher::class, GuzzleFetcher::class)`,
  `singletonIf(HostResolver::class, SystemHostResolver::class)`) and
  `CONFIGURATION_CHECKS['fetcher']`; `config/sso.php`: `fetcher`.

## Authoritative Tests

- `tests/Unit/Fetching/AddressPolicyTest.php`.
- `tests/Feature/Fetching/GuzzleFetcherTest.php`, `tests/Feature/Fetching/GuzzleFetcherRedirectsTest.php`,
  `tests/Feature/Fetching/GuzzleFetcherCredentialsTest.php`.
- `tests/Feature/Fetching/FetcherSettingsTest.php`, `tests/Feature/Fetching/FetcherCheckTest.php`.
- `tests/Integration/Fetching/CurlHandlerTest.php`.
- `tests/Integration/Fetching/TlsTransportTest.php`: real transfers through cURL to a local HTTPS server, showing the
  pin is honoured, the certificate and host name are verified, and a body past the cap is aborted mid-transfer.
- `tests/Unit/Testing/FakeFetcherTest.php`.
- `tests/Unit/Fetching/FetchRequestTest.php`, `tests/Unit/Fetching/FetchCredentialsTest.php`,
  `tests/Unit/Fetching/FetchResultTest.php`, `tests/Unit/Fetching/CappedSinkTest.php`.

## Change Triggers

- A new outbound request, or a request to an identity provider that does not go through `Contracts\Fetcher`.
- A change to a built-in range, a carrying IPv6 form, or how a configured range is read.
- A change to URL or host normalisation, the IP-literal rule, resolution, or pinning.
- A change to the transport options, the handler, or the Guzzle major versions supported.
- A change to the caps, the redirect rules or the credentials each purpose sends.
- A change to what a refusal or failure carries or logs.
