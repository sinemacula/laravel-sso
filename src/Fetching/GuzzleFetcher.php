<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use GuzzleHttp\Client;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Uri;
use GuzzleHttp\Psr7\UriResolver;
use GuzzleHttp\Psr7\Utils;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\UriInterface;
use Psr\Log\LoggerInterface;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\HostResolver;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;

/**
 * The default fetcher: Guzzle on cURL, pinned with `CURLOPT_RESOLVE` to the
 * address it checked so DNS rebinding cannot move it. Nothing is retried.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class GuzzleFetcher implements Fetcher
{
    /** @var string The `User-Agent` every request carries. */
    public const string USER_AGENT = 'laravel-sso';

    /** @var int The port of a URL that names none. */
    private const int HTTPS_PORT = 443;

    /** @var string The type of a token request's body. */
    private const string FORM_TYPE = 'application/x-www-form-urlencoded';

    /** @var string The `client_assertion_type` of a signed client assertion (RFC 7523). */
    private const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /** @var string A control character, space, DEL or backslash, which could be read two ways. */
    private const string UNSAFE_CHARACTER = '/[\x00-\x20\x7F\\\]/';

    /** @var string The authority of a URL, as written. */
    private const string AUTHORITY = '#^[^:/?\#]+://([^/?\#]*)#';

    /** @var string A byte over 0x7F. */
    private const string NON_ASCII = '/[\x80-\xFF]/';

    /** @var string A URL's scheme with `://`, its authority, and the rest. */
    private const string URL_PARTS = '#^([^:/?\#]+://)([^/?\#]*)(.*)$#sD';

    /** @var string An authority of a host without `@` or `[`, and an optional decimal port. */
    private const string HOST_AND_PORT = '/^([^@\[\]:]+)(:[0-9]*)?$/D';

    /** @var string A normalised host name of letters, digits, hyphens and underscores. */
    private const string HOST_NAME = '/^[a-z0-9_-]+(?:\.[a-z0-9_-]+)*$/D';

    /** @var string A host of digits, dots and `x`, which a parser may read as IPv4. */
    private const string NUMERIC_HOST = '/^[0-9.x]+$/iD';

    /** @var string A host ending in a numeric label, which a parser may read as IPv4. */
    private const string NUMERIC_LAST_LABEL = '/(?:^|\.)(?:0x[0-9a-f]*|[0-9]+)$/iD';

    /** @var string The message when the cURL handler is unavailable. */
    private const string NO_CURL = 'The outbound fetcher needs the PHP extension `curl`: it pins the address it checked with CURLOPT_RESOLVE and never falls back to PHP streams.';

    /** @var callable(\Psr\Http\Message\RequestInterface, array<string, mixed>): \GuzzleHttp\Promise\PromiseInterface The Guzzle handler. */
    private mixed $handler;

    /** @var bool Whether to set the cURL options Guzzle 8 manages itself. */
    private bool $setsManagedCurlOptions;

    /** @var \Closure(): int The monotonic clock in nanoseconds. */
    private \Closure $monotonicClock;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Fetching\AddressPolicy  $policy
     * @param  \Psr\Log\LoggerInterface  $logger
     * @param  \SineMacula\Laravel\Sso\Contracts\HostResolver  $resolver
     * @param  ?callable(\Psr\Http\Message\RequestInterface, array<string, mixed>): \GuzzleHttp\Promise\PromiseInterface  $handler
     * @param  ?\Closure(): bool  $curlLoaded
     * @param  ?\Closure(): int  $monotonicClock
     *
     * @throws \LogicException
     */
    public function __construct(

        /** The time and size caps and the redirect limit. */
        private FetcherSettings $settings,

        /** Which addresses are refused. */
        private AddressPolicy $policy,

        /** Where refusals and failures are reported. */
        private LoggerInterface $logger,

        /** What resolves a host name: the container's `HostResolver`. */
        private HostResolver $resolver,

        // Not promoted: defaults to cURL's handler; a test gives a mock
        ?callable $handler = null,

        // Not promoted: only read here, to simulate a missing ext-curl
        ?\Closure $curlLoaded = null,

        // Not promoted: defaults to `hrtime(true)`
        ?\Closure $monotonicClock = null,
    ) {
        $curlLoaded ??= static fn (): bool => extension_loaded('curl') && function_exists('curl_init');

        if ($handler === null && !$curlLoaded()) {
            throw new \LogicException(self::NO_CURL);
        }

        $version = (new \ReflectionClassConstant(ClientInterface::class, 'MAJOR_VERSION'))->getValue();

        $this->handler                = $handler ?? new CurlHandler;
        $this->setsManagedCurlOptions = !is_int($version) || $version < 8;
        $this->monotonicClock         = $monotonicClock ?? static fn (): int => (int) hrtime(true);
    }

    /**
     * Send the request, or refuse it, within one deadline for every hop.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function fetch(FetchRequest $request): FetchResult
    {
        $deadline = FetchDeadline::in($request->timeoutSeconds ?? $this->settings->timeoutSeconds(), $this->monotonicClock);

        return $this->hop($request, $request->url, 0, $deadline);
    }

    /**
     * Check, resolve, pin and send one URL. The deadline is checked either side
     * of the lookup, since PHP cannot cut a lookup short.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  string  $url
     * @param  int  $redirects
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchDeadline  $deadline
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    private function hop(FetchRequest $request, string $url, int $redirects, FetchDeadline $deadline): FetchResult
    {
        $target = self::target($url);

        if (isset($target['cause'])) {
            return $this->stop($request, FetchResult::refused(), $target['cause'], $target['host']);
        }

        $addresses = match (true) {
            $deadline->hasPassed()      => [],
            $target['literal'] !== null => [$target['literal']],
            default                     => $this->resolver->addresses($target['host']),
        };

        $unusable = $this->unusableAddresses($request, $target['host'], $addresses, $deadline);

        if ($unusable !== null) {
            return $unusable;
        }

        $result = $this->send($request, $target, $addresses[0], $redirects === 0, $deadline);

        return $this->follow($request, $target, $result, $redirects, $deadline);
    }

    /**
     * Stop a hop out of time or addresses, or with any refused address, so a
     * split answer cannot slip a private one through; otherwise `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  string  $host
     * @param  list<string>  $addresses
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchDeadline  $deadline
     * @return ?\SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    private function unusableAddresses(FetchRequest $request, string $host, array $addresses, FetchDeadline $deadline): ?FetchResult
    {
        $stop = match (true) {
            $deadline->hasPassed()                                         => [FetchResult::failed(), 'timeout'],
            $addresses === []                                              => [FetchResult::failed(), 'unresolved'],
            array_filter($addresses, $this->policy->isRefused(...)) !== [] => [FetchResult::refused(), 'refused_address'],
            default                                                        => null,
        };

        return $stop === null ? null : $this->stop($request, $stop[0], $stop[1], $host);
    }

    /**
     * Follow a redirect for an uncredentialed request within the limit, or
     * return the hop's result.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  array{uri: \Psr\Http\Message\UriInterface, host: string, port: int, literal: ?string}  $target
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @param  int  $redirects
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchDeadline  $deadline
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    private function follow(FetchRequest $request, array $target, FetchResult $result, int $redirects, FetchDeadline $deadline): FetchResult
    {
        $location = $result->header('location');
        $status   = $result->statusCode ?? 0;

        if ($location === null || $status < 300 || $status > 399) {
            return $result;
        }

        $stop = match (true) {
            $request->purpose->isCredentialed()           => [FetchResult::refused(), 'redirect_refused'],
            $redirects >= $this->settings->maxRedirects() => [FetchResult::failed(), 'too_many_redirects'],
            default                                       => null,
        };

        if ($stop !== null) {
            return $this->stop($request, $stop[0], $stop[1], $target['host']);
        }

        return $this->hop($request, self::redirectTarget($target['uri'], $location), $redirects + 1, $deadline);
    }

    /**
     * Send one checked URL pinned to the address, with the method, credential
     * and body on the first hop only; never log the exception's message.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  array{uri: \Psr\Http\Message\UriInterface, host: string, port: int, literal: ?string}  $target
     * @param  string  $address
     * @param  bool  $first
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchDeadline  $deadline
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    private function send(FetchRequest $request, array $target, string $address, bool $first, FetchDeadline $deadline): FetchResult
    {
        $cap      = $request->maxBytes ?? $this->settings->maxResponseBytes();
        $tooLarge = false;
        $sink     = new CappedSink($cap);
        $client   = new Client(['handler' => HandlerStack::create($this->handler)]);
        $options  = [...$this->options($request, $target, $address, $first, $cap, $tooLarge), 'sink' => $sink->stream()];
        $timeouts = $deadline->transferTimeouts($this->settings->connectTimeoutSeconds());

        if ($timeouts === null) {
            return $this->stop($request, FetchResult::failed(), 'timeout', $target['host']);
        }

        try {
            $response = $client->request($first ? $request->method() : 'GET', $target['uri'], [...$options, ...$timeouts]);
            $body     = CappedSink::read($response->getBody(), $cap);
        } catch (GuzzleException|\InvalidArgumentException|\RuntimeException $exception) {
            $cause = match (true) {
                $tooLarge || $sink->exceeded() => 'too_large',
                $deadline->hasPassed()         => 'timeout',
                default                        => 'transfer',
            };

            return $this->stop($request, FetchResult::failed(), $cause, $target['host'], $exception);
        }

        /** @var array<string, string> $headers */
        $headers = array_map(static fn (array $values): string => $values[0] ?? '', $response->getHeaders());

        return $tooLarge || $sink->exceeded() || strlen($body) > $cap
            ? $this->stop($request, FetchResult::failed(), 'too_large', $target['host'])
            : FetchResult::fetched($response->getStatusCode(), $headers, $body);
    }

    /**
     * The Guzzle options of one hop, but for the time caps and the sink, which
     * enforces the size cap on every Guzzle.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  array{uri: \Psr\Http\Message\UriInterface, host: string, port: int, literal: ?string}  $target
     * @param  string  $address
     * @param  bool  $first
     * @param  int  $cap
     * @param  bool  $tooLarge
     * @return array<string, mixed>
     */
    private function options(FetchRequest $request, array $target, string $address, bool $first, int $cap, bool &$tooLarge): array
    {
        $options = [
            'allow_redirects' => false,
            'http_errors'     => false,
            'verify'          => true,
            'cookies'         => false,
            'proxy'           => '',
            'decode_content'  => false,
            'protocols'       => ['https'],
            'curl'            => $this->curlOptions($target, $address),
            // Guzzle 7's mock handler also passes a queued failure here, which
            // has no headers to check
            'on_headers' => static function (mixed $response) use ($cap, &$tooLarge): void {
                if (!$response instanceof ResponseInterface) {
                    return;
                }

                $length = $response->getHeaderLine('Content-Length');

                if (preg_match('/^\d+$/D', $length) === 1 && (int) $length > $cap) {
                    $tooLarge = true;

                    throw new \OverflowException('The response declares a length over the cap.');
                }
            },
            // Guzzle passes download expected and received, then upload ones
            'progress' => static function (float|int ...$transfer) use ($cap, &$tooLarge): bool {
                if (($transfer[1] ?? 0) > $cap) {
                    $tooLarge = true;
                }

                return $tooLarge;
            },
        ];

        $headers = [
            'User-Agent' => self::USER_AGENT,
            'Accept'     => match ($request->purpose) {
                FetchPurpose::METADATA => 'application/samlmetadata+xml, application/xml;q=0.9, text/xml;q=0.8',
                FetchPurpose::JWKS     => 'application/jwk-set+json, application/json;q=0.9',
                default                => 'application/json',
            },
        ];

        return $first ? self::authenticated($request, $options, $headers) : [...$options, 'headers' => $headers];
    }

    /**
     * Add the request's one credential where its kind says, and a token
     * request's form-encoded body.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  array<string, mixed>  $options
     * @param  array<string, string>  $headers
     * @return array<string, mixed>
     */
    private static function authenticated(FetchRequest $request, array $options, array $headers): array
    {
        $form        = $request->form();
        $credentials = $request->credentials;

        if ($credentials !== null) {
            $clientId = (string) $credentials->clientId;
            $secret   = $credentials->secret();

            [$headers, $form] = match ($credentials->kind) {
                CredentialKind::CLIENT_SECRET_BASIC => [[...$headers, 'Authorization' => 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret))], $form],
                CredentialKind::CLIENT_SECRET_POST  => [$headers, [...$form, 'client_id' => $clientId, 'client_secret' => $secret]],
                CredentialKind::PRIVATE_KEY_JWT     => [$headers, [
                    ...$form,
                    'client_id'             => $clientId,
                    'client_assertion_type' => self::ASSERTION_TYPE,
                    'client_assertion'      => $secret,
                ]],
                CredentialKind::ACCESS_TOKEN => [[...$headers, 'Authorization' => 'Bearer ' . $secret], $form],
            };
        }

        if ($request->purpose === FetchPurpose::TOKEN) {
            $headers['Content-Type'] = self::FORM_TYPE;
            $options['body']         = http_build_query($form, '', '&', PHP_QUERY_RFC1738);
        }

        return [...$options, 'headers' => $headers];
    }

    /**
     * The cURL options of one hop; Guzzle 8 sets the protocol, redirect and
     * proxy options itself and refuses them here.
     *
     * @param  array{uri: \Psr\Http\Message\UriInterface, host: string, port: int, literal: ?string}  $target
     * @param  string  $address
     * @return array<int, mixed>
     */
    private function curlOptions(array $target, string $address): array
    {
        $bytes     = (string) inet_pton($address);
        $canonical = (string) inet_ntop($bytes);
        $pinned    = strlen($bytes)     === 16 ? '[' . $canonical . ']' : $canonical;
        $options   = $target['literal'] === null ? [CURLOPT_RESOLVE => [sprintf('%s:%d:%s', $target['host'], $target['port'], $pinned)]] : [];

        if (!$this->setsManagedCurlOptions) {
            return $options;
        }

        return $options + [
            CURLOPT_PROTOCOLS       => CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_FOLLOWLOCATION  => false,
            CURLOPT_NOPROXY         => '*',
        ];
    }

    /**
     * The URL checked and normalised for sending, or the refusal cause with any
     * normalised host.
     *
     * @param  string  $url
     * @return array{cause: string, host: ?string}|array{uri: \Psr\Http\Message\UriInterface, host: string, port: int, literal: ?string}
     */
    private static function target(string $url): array
    {
        $parsed = self::parsed($url);

        if ($parsed === null) {
            return ['cause' => 'malformed', 'host' => null];
        }

        [$url, $parts, $host] = $parsed;

        $cause = self::refusalOf($url, $parts) ?? self::ipFormRefusalOf($host);
        $uri   = $cause === null ? self::uriOf($host, $parts) : null;

        if ($uri === null) {
            return ['cause' => $cause ?? 'malformed', 'host' => $host];
        }

        return ['uri' => $uri, 'host' => $host, 'port' => $parts['port'] ?? self::HTTPS_PORT, 'literal' => self::literalOf($host)];
    }

    /**
     * The ASCII URL, its parts and its normalised host, or `null` when any of
     * them cannot be had.
     *
     * @param  string  $url
     * @return ?array{string, array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, query?: string, path?: string, fragment?: string}, string}
     */
    private static function parsed(string $url): ?array
    {
        $ascii = preg_match(self::UNSAFE_CHARACTER, $url) === 1 ? null : self::asciiUrl($url);
        $parts = $ascii                                   === null ? false : parse_url($ascii);
        $host  = is_array($parts) ? self::asciiHost($parts['host'] ?? '') : null;

        return $ascii !== null && is_array($parts) && $host !== null ? [$ascii, $parts, $host] : null;
    }

    /**
     * The URI to send, or `null` when Guzzle refuses a part.
     *
     * @param  string  $host
     * @param  array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, query?: string, path?: string, fragment?: string}  $parts
     * @return ?\Psr\Http\Message\UriInterface
     */
    private static function uriOf(string $host, array $parts): ?UriInterface
    {
        try {
            $uri = (new Uri)->withScheme('https')->withHost($host)->withPath($parts['path'] ?? '')->withQuery($parts['query'] ?? '');

            return isset($parts['port']) ? $uri->withPort($parts['port']) : $uri;
        } catch (\InvalidArgumentException) {
            return null;
        }
    }

    /**
     * The URL in ASCII, since `parse_url()` rewrites some bytes over 0x7F, or
     * `null` when its authority cannot be converted.
     *
     * @param  string  $url
     * @return ?string
     */
    private static function asciiUrl(string $url): ?string
    {
        if (preg_match(self::NON_ASCII, $url) !== 1) {
            return $url;
        }

        $authority = preg_match(self::URL_PARTS, $url, $matches) === 1 ? self::asciiAuthority($matches[2]) : null;

        if ($authority === null) {
            return null;
        }

        return $matches[1] . $authority . preg_replace_callback(self::NON_ASCII, static fn (array $byte): string => rawurlencode($byte[0]), $matches[3]);
    }

    /**
     * The authority in ASCII, or `null` unless it converts to a plain host
     * name, so a character that converts to `:` or `@` is refused.
     *
     * @param  string  $authority
     * @return ?string
     */
    private static function asciiAuthority(string $authority): ?string
    {
        if (preg_match(self::NON_ASCII, $authority) !== 1) {
            return $authority;
        }

        $host = preg_match(self::HOST_AND_PORT, $authority, $parts) === 1 ? self::asciiHost($parts[1]) : null;

        return $host === null ? null : $host . ($parts[2] ?? '');
    }

    /**
     * Why the URL's scheme, userinfo, fragment or port is refused, or `null`.
     *
     * @param  string  $url
     * @param  array{scheme?: string, host?: string, port?: int, user?: string, pass?: string, query?: string, path?: string, fragment?: string}  $parts
     * @return ?string
     */
    private static function refusalOf(string $url, array $parts): ?string
    {
        $authority = preg_match(self::AUTHORITY, $url, $matches) === 1 ? $matches[1] : '';

        return match (true) {
            strtolower($parts['scheme'] ?? '') !== 'https'                                    => 'scheme',
            isset($parts['user'])   || isset($parts['pass']) || str_contains($authority, '@') => 'userinfo',
            str_contains($url, '#') || (isset($parts['port']) && $parts['port'] < 1)          => 'malformed',
            default                                                                           => null,
        };
    }

    /**
     * The host lower-cased and IDNA-converted with one trailing dot stripped,
     * or `null` when it is not a plain host name.
     *
     * @param  string  $host
     * @return ?string
     */
    private static function asciiHost(string $host): ?string
    {
        $host = strtolower($host);

        if (str_starts_with($host, '[')) {
            return str_ends_with($host, ']') ? $host : null;
        }

        $ascii = $host  === '' ? false : idn_to_ascii($host, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
        $ascii = $ascii === false ? '' : strtolower($ascii);
        $ascii = str_ends_with($ascii, '.') ? substr($ascii, 0, -1) : $ascii;

        return strlen($ascii) <= 253 && preg_match(self::HOST_NAME, $ascii) === 1 ? $ascii : null;
    }

    /**
     * `ip_form` when the host may be read as a non-canonical IP literal, such
     * as `0x7f.1` or `127.1`; `null` otherwise.
     *
     * @param  string  $host
     * @return ?string
     */
    private static function ipFormRefusalOf(string $host): ?string
    {
        if (str_starts_with($host, '[')) {
            return self::literalOf($host) === null ? 'ip_form' : null;
        }

        if (preg_match(self::NUMERIC_HOST, $host) !== 1 && preg_match(self::NUMERIC_LAST_LABEL, $host) !== 1) {
            return null;
        }

        return self::literalOf($host) === null ? 'ip_form' : null;
    }

    /**
     * The address of a canonical IP literal host, or `null`.
     *
     * @param  string  $host
     * @return ?string
     */
    private static function literalOf(string $host): ?string
    {
        $bracketed = str_starts_with($host, '[') && str_ends_with($host, ']');
        $address   = $bracketed ? substr($host, 1, -1) : $host;
        $flag      = $bracketed ? FILTER_FLAG_IPV6 : FILTER_FLAG_IPV4;

        if (filter_var($address, FILTER_VALIDATE_IP, $flag) === false) {
            return null;
        }

        $bytes = inet_pton($address);

        return $bytes !== false && inet_ntop($bytes) === $address ? $address : null;
    }

    /**
     * Resolve a redirect's `Location`; an unparsable one is returned as is for
     * the next hop to refuse.
     *
     * @param  \Psr\Http\Message\UriInterface  $base
     * @param  string  $location
     * @return string
     */
    private static function redirectTarget(UriInterface $base, string $location): string
    {
        try {
            return (string) UriResolver::resolve($base, Utils::uriFor($location));
        } catch (\InvalidArgumentException) {
            return $location;
        }
    }

    /**
     * Log a refusal or failure once, never the URL path, query, form,
     * credential, headers or body, and return it.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $result
     * @param  string  $cause
     * @param  ?string  $host
     * @param  ?\Throwable  $exception
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     */
    private function stop(FetchRequest $request, FetchResult $result, string $cause, ?string $host, ?\Throwable $exception = null): FetchResult
    {
        $context = [
            'purpose' => $request->purpose->value,
            'reason'  => $result->reason?->value,
            'cause'   => $cause,
            'host'    => $host,
        ];

        if ($exception !== null) {
            $context['exception_class'] = $exception::class;
        }

        $this->logger->warning('sso.fetch.' . $result->status->value, $context);

        return $result;
    }
}
