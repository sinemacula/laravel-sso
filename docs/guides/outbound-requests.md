# Outbound Requests

Every request the package makes to an identity provider (SAML metadata, OpenID discovery, a JWKS, the token endpoint
and UserInfo) goes through one fetcher, `SineMacula\Laravel\Sso\Contracts\Fetcher`. The addresses involved are ones an
administrator typed in or that an identity provider's metadata supplied, so the default fetcher treats each as
untrusted:

- it sends only `https`, and always verifies the server's certificate and host name;
- it refuses a URL with userinfo or a fragment, and an IP address written any way but its plain form (`2130706433`,
  `0177.0.0.1`, `0x7f.1`, `127.1`);
- it resolves the host once and refuses it if any address it resolves to is loopback, private, link-local,
  unique-local, multicast, reserved, a cloud metadata address (`169.254.169.254`, `fd00:ec2::254`) or one of your own
  refused ranges, IPv6 forms that carry an IPv4 address included;
- it connects to the address it checked, so a second lookup cannot send it elsewhere;
- it never uses a proxy, cookies or compressed responses;
- it follows no redirect for a token or UserInfo request, and checks each redirect of any other request the same way;
- it caps the time taken and the size of the response;
- it sends credentials by purpose only: none to metadata, discovery or a JWKS, the connection's client authentication
  to the token endpoint, and only the access token to UserInfo.

A refused or failed request comes back as a reason code (`fetch_refused` or `fetch_failed`); what went wrong is logged
as a warning (`sso.fetch.refused` or `sso.fetch.failed`) with the purpose, a short cause, the host and the exception's
class, never the URL's path or query, a credential or the response.

The default fetcher needs PHP's `curl` extension, which it uses to connect to the address it checked. Without it the
fetcher refuses to start rather than fall back to PHP streams, and `php artisan sso:check` reports it under `[fetcher]`.

## Settings

| Key                               | Default   | Env                                   | Range                              |
|-----------------------------------|-----------|---------------------------------------|------------------------------------|
| `fetcher.timeout_seconds`         | `10`      | `SSO_FETCHER_TIMEOUT_SECONDS`         | `1` to `60`                        |
| `fetcher.connect_timeout_seconds` | `5`       | `SSO_FETCHER_CONNECT_TIMEOUT_SECONDS` | `1` to `30`, at most the timeout   |
| `fetcher.max_response_bytes`      | `1048576` | `SSO_FETCHER_MAX_RESPONSE_BYTES`      | `1024` to `10485760` (10 MiB)      |
| `fetcher.max_redirects`           | `3`       | `SSO_FETCHER_MAX_REDIRECTS`           | `0` to `10`                        |
| `fetcher.refused_ranges`          | `[]`      |                                       | a list of IPv4 or IPv6 CIDR ranges |

- `timeout_seconds` is the time one fetch may take in all: resolving the host, connecting, the last byte, and every
  redirect it follows, which share the one budget rather than each starting a fresh one. `connect_timeout_seconds` is
  the time connecting may take, never more than what is left of the timeout. A fetch that runs out of time fails as
  `fetch_failed`, logged with the cause `timeout`.
- `max_response_bytes` is the largest response body accepted, counted as received (responses are never decompressed).
  A larger one fails, however it is sent. SAML metadata is the one exception: it is held to its own cap,
  `sso.metadata.max_bytes` (1 MiB by default, up to 256 MiB), so a federation's aggregate can be allowed without
  raising the cap of every token, UserInfo and JWKS response (see
  [SAML metadata](saml-metadata.md#large-federation-metadata)). A fetcher you bind yourself must honour a request's own
  cap (`FetchRequest::$maxBytes`) when it carries one.
- `max_redirects` is how many redirects a metadata, discovery or JWKS request may follow, each checked again. A token
  or UserInfo request follows none, whatever this is set to.

A value outside its range, or not a whole number, fails closed when the fetcher reads it, and stops the boot outside the
console, with a message naming the key and its range (`sso.fetcher.timeout_seconds must be an integer from 1 to 60.`);
`php artisan sso:check` reports each under `[fetcher]`, as it does a connect timeout longer than the timeout.

## Refusing more addresses

The built-in refused ranges cannot be removed. To refuse more (a peered network, a partner's range, your own public
addresses), list them as CIDR ranges in the `fetcher` section of `config/sso.php`:

<!-- snippet: tests/Integration/Examples/OutboundRequests/config/sso.php#outbound-refused-ranges -->
```php
'fetcher' => [
    'refused_ranges' => [
        '203.0.114.0/24',  // a partner's IPv4 network
        '198.51.101.7/32', // one of your own public IPv4 addresses
        '3fff:42::/32',    // an IPv6 range
    ],
],
```

An IPv4 range is `/0` to `/32` and an IPv6 range `/0` to `/128`. An IPv4 range also refuses that address carried in an
IPv6 form (`::ffff:203.0.114.5`, `64:ff9b::203.0.114.5`). The list must be a plain list of strings; an entry that is not
a CIDR range fails with its key, `sso.fetcher.refused_ranges.2 must be a CIDR range: ...`.

## Using an egress proxy

The default fetcher never uses a proxy, including one set in the environment (`HTTPS_PROXY`), because a proxy would
make its own connection to an address the fetcher did not check. If your network requires outbound traffic to go
through a proxy, bind your own `SineMacula\Laravel\Sso\Contracts\Fetcher` in your service provider's `register()`:

<!-- snippet: tests/Integration/Examples/OutboundRequests/EgressProxyServiceProvider.php#outbound-proxied-fetcher -->
```php
// One fetcher per request or job, as the package's own is bound
$this->app->scoped(Fetcher::class, ProxiedFetcher::class);
```

Your fetcher takes on what the default one guarantees, and the package relies on it:

- `https` only, with certificate and host name verification;
- the same refused addresses and your refused ranges (reuse `SineMacula\Laravel\Sso\Fetching\AddressPolicy`, or a
  proxy that enforces an equivalent allow-list), checked for the address actually connected to;
- no redirect for a request whose purpose carries a credential (`$request->purpose->isCredentialed()`), and each
  other redirect checked again;
- the size and time caps;
- the request's one credential (`$request->credentials`) sent as its kind says, and nothing else;
- a refusal or failure answered as `FetchResult::refused()` or `FetchResult::failed()`, never thrown, with nothing of
  the request's form, credential or the response's body in a log, an exception or an event.

If you only need a different DNS resolver (a bounded timeout, DNSSEC, DNS over HTTPS), keep the default fetcher and bind
`SineMacula\Laravel\Sso\Contracts\HostResolver` instead. Its `addresses(string $asciiHost): array` answers every A and
AAAA address of the name, or `[]` when there are none; it should not throw for a name that does not resolve.

## Slow DNS

The default resolver asks the system resolver through PHP's `dns_get_record()`, which has no timeout of its own and
which PHP cannot interrupt, so a slow resolver holds the request or queue worker until it answers. The fetcher counts
the lookup against the timeout and checks it the moment the lookup returns: one that ran past it fails the fetch as a
timeout and nothing is sent. What it cannot do is cut the lookup short. If your resolver can be slow, bind a
`HostResolver` whose lookup is bounded (a DNS client with its own timeout, say) and answers `[]` when that runs out, in
your service provider's `register()`:

<!-- snippet: tests/Integration/Examples/OutboundRequests/BoundedDnsServiceProvider.php#outbound-host-resolver -->
```php
// One resolver for every request and job: it keeps no state
$this->app->singleton(HostResolver::class, BoundedHostResolver::class);
```

## A fake fetcher in tests

`SineMacula\Laravel\Sso\Testing\FakeFetcher` answers each URL with the response you give it and records every request,
so your tests never reach an identity provider. Bind it in place of the package's fetcher, give each URL its response,
run the code under test, and assert what it fetched:

<!-- snippet: tests/Integration/Examples/OutboundRequests/OutboundRequestsExampleTest.php#outbound-fake-fetcher -->
```php
$idp      = new FakeSamlIdentityProvider;
$provider = new FakeOpenIdProvider('https://op.example.com');

$fetcher = (new FakeFetcher)
    ->respond('https://idp.example.com/metadata', FetchResult::fetched(200, ['Content-Type' => 'application/xml'], $idp->metadata()->toXml()))
    ->respond('https://op.example.com/.well-known/openid-configuration', FetchResult::fetched(200, [], (string) json_encode($provider->discovery())))
    ->respond('https://op.example.com/jwks', FetchResult::failed());

$this->instance(Fetcher::class, $fetcher);

// The code under test: import each provider's metadata
$saml = app(MetadataImporter::class)->importUrl('tenant-1', null, 'https://idp.example.com/metadata', $idp->entityId);
$oidc = app(DiscoveryImporter::class)->import('tenant-1', 'https://op.example.com');

self::assertTrue($saml->isProposed());
self::assertSame(FailureReason::FETCH_FAILED, $oidc->reason);

// A closure builds the response when the request is made
$fetcher->respond('https://op.example.com/jwks', static fn (): FetchResult => FetchResult::fetched(200, [], (string) json_encode($provider->jwks())));

self::assertTrue(app(DiscoveryImporter::class)->import('tenant-1', 'https://op.example.com')->isProposed());

$fetcher->assertFetched('https://idp.example.com/metadata', FetchPurpose::METADATA);
$fetcher->assertFetched('https://op.example.com/jwks', FetchPurpose::JWKS);
```

| Method                                                      | What it does                                                          |
|-------------------------------------------------------------|-----------------------------------------------------------------------|
| `respond(string $url, FetchResult\|Closure $response)`      | Answers every request to the URL; a closure is given the request      |
| `fetch(FetchRequest $request)`                              | Records the request and answers it; throws for a URL with no response |
| `requests()`                                                | Every request made, in order                                          |
| `assertFetched(string $url, ?FetchPurpose $purpose = null)` | Fails unless the URL was fetched, for the purpose when one is given   |
| `assertNothingFetched()`                                    | Fails if anything was fetched                                         |

A URL is matched exactly as the request carries it, and a later response to it replaces an earlier one, as the JWKS's
does above. A request to a URL you gave no response throws a `LogicException` naming the URL, so an unexpected request
fails your test instead of passing unnoticed. The fake applies none of the default fetcher's checks but one: a request
that carries its own size cap (a metadata request's) fails as `fetch_failed` when the body you gave is longer. Use
`FetchResult::refused()` or `FetchResult::failed()` to test how your code handles a refused or failed fetch.
