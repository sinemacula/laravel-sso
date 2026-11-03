<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\OutboundRequests;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\FnStream;
use GuzzleHttp\Psr7\Utils;
use Illuminate\Contracts\Config\Repository;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Fetching\Enums\CredentialKind;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;
use SineMacula\Laravel\Sso\Fetching\FetcherSettings;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;

/**
 * The application's own fetcher, for a network whose outbound traffic must
 * leave through an egress proxy (SSO-2.9), keeping what the package's fetcher
 * guarantees:
 *
 * - `https` only, through the proxy named by `services.egress.proxy`, with the
 *   certificate and host name verified, and no proxy from the environment;
 * - no user information or fragment in the URL, no IP address written but in
 *   its plain form, and no IP address the package's `AddressPolicy` refuses,
 *   the application's own refused ranges included; a host name is resolved and
 *   connected to by the proxy, whose allow-list refuses the same addresses;
 * - no redirect followed, for any purpose, so a `3xx` comes back as the
 *   response it is, which the package treats as a failure;
 * - the request's own timeout, or `sso.fetcher.timeout_seconds`, for the whole
 *   request, and its own size cap, or `sso.fetcher.max_response_bytes`, the
 *   transfer stopped once the body passes it;
 * - the request's one credential sent as its kind says, and nothing else: no
 *   cookie and no compressed response;
 * - a refusal or failure answered as a result, never thrown, and nothing of the
 *   request's form, credential or the response's body logged or reported.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProxiedFetcher implements Fetcher
{
    /** @var string The `client_assertion_type` of a signed client assertion (RFC 7523 §2.2). */
    private const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /** @var string A host whose last label is a number, which a parser may read as an IPv4 address. */
    private const string NUMERIC_LAST_LABEL = '/(?:^|\.)(?:0x[0-9a-f]*|[0-9]+)$/iD';

    /** @var \GuzzleHttp\Client The client every request leaves through, by way of the proxy. */
    private Client $client;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     * @param  \SineMacula\Laravel\Sso\Fetching\AddressPolicy  $policy
     * @param  (callable(\Psr\Http\Message\RequestInterface, array<string, mixed>): \GuzzleHttp\Promise\PromiseInterface)|null  $handler
     *
     * @throws \LogicException
     */
    public function __construct(

        // Not promoted: only the proxy is read from it, once
        Repository $config,

        /** The package's time and size caps. */
        private FetcherSettings $settings,

        /** The addresses the package refuses, the application's ranges included. */
        private AddressPolicy $policy,

        // Not promoted: Guzzle's own handler stands in when none is given; a
        // test gives one that answers without a network
        ?callable $handler = null,
    ) {
        $proxy = $config->get('services.egress.proxy');

        if (!is_string($proxy) || $proxy === '') {
            throw new \LogicException('services.egress.proxy must name the egress proxy.');
        }

        $this->client = new Client([
            'handler'         => HandlerStack::create($handler),
            'proxy'           => ['https' => $proxy],
            'verify'          => true,
            'allow_redirects' => false,
            'http_errors'     => false,
            'decode_content'  => false,
            'cookies'         => false,
        ]);
    }

    /**
     * Send the request through the proxy, or refuse it.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return \SineMacula\Laravel\Sso\Fetching\FetchResult
     *
     * @throws \InvalidArgumentException
     */
    #[\Override]
    public function fetch(FetchRequest $request): FetchResult
    {
        if ($this->isRefused($request->url)) {
            return FetchResult::refused();
        }

        $sink = Utils::streamFor(Utils::tryFopen('php://temp', 'w+b'));

        try {
            $response = $this->client->request($request->method(), $request->url, $this->options($request, $sink));
        } catch (GuzzleException|\RuntimeException) {
            return FetchResult::failed();
        }

        $sink->rewind();

        return FetchResult::fetched($response->getStatusCode(), self::headers($response), $sink->getContents());
    }

    /**
     * Whether the URL may not be sent: it is not `https`, has no host, carries
     * user information or a fragment, writes an IP address in any but its plain
     * form, or names an IP address that is refused.
     *
     * @param  string  $url
     * @return bool
     *
     * @throws \InvalidArgumentException
     */
    private function isRefused(string $url): bool
    {
        $parts = parse_url($url);

        if (!is_array($parts)) {
            return true;
        }

        $host    = trim($parts['host'] ?? '', '[]');
        $literal = filter_var($host, FILTER_VALIDATE_IP) !== false;

        return in_array(true, [
            strtolower($parts['scheme'] ?? '') !== 'https',
            $host === '',
            isset($parts['user']) || isset($parts['pass']),
            isset($parts['fragment']),
            !$literal && preg_match(self::NUMERIC_LAST_LABEL, $host) === 1,
            $literal  && $this->policy->isRefused($host),
        ], true);
    }

    /**
     * The Guzzle options of the request: its time cap, its size cap on the sink
     * the body is written to, and its credential and form.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @param  \Psr\Http\Message\StreamInterface  $sink
     * @return array<string, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function options(FetchRequest $request, StreamInterface $sink): array
    {
        $timeout = $request->timeoutSeconds ?? $this->settings->timeoutSeconds();

        [$headers, $form] = self::credentialed($request);

        $options = [
            'timeout'         => $timeout,
            'connect_timeout' => min($this->settings->connectTimeoutSeconds(), $timeout),
            'sink'            => self::capped($sink, $request->maxBytes ?? $this->settings->maxResponseBytes()),
            'headers'         => $headers,
        ];

        return $request->purpose === FetchPurpose::TOKEN ? [...$options, 'form_params' => $form] : $options;
    }

    /**
     * The sink, refusing a write that would take the body past the cap, which
     * stops the transfer.
     *
     * @param  \Psr\Http\Message\StreamInterface  $sink
     * @param  int  $cap
     * @return \Psr\Http\Message\StreamInterface
     */
    private static function capped(StreamInterface $sink, int $cap): StreamInterface
    {
        return FnStream::decorate($sink, [
            'write' => static function (string $bytes) use ($sink, $cap): int {

                if ((int) $sink->getSize() + strlen($bytes) > $cap) {
                    throw new \RuntimeException('The response is larger than its cap.');
                }

                return $sink->write($bytes);
            },
        ]);
    }

    /**
     * The headers and form of the request with its one credential where its
     * kind says: a client id and secret in the `Authorization: Basic` header,
     * each form-encoded first (RFC 6749 §2.3.1), or in the form; a client id
     * and signed client assertion in the form (RFC 7523 §2.2); or an access
     * token in the `Authorization: Bearer` header (RFC 6750 §2.1).
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchRequest  $request
     * @return array{0: array<string, string>, 1: array<string, string>}
     */
    private static function credentialed(FetchRequest $request): array
    {
        $credentials = $request->credentials;
        $form        = $request->form();

        if ($credentials === null) {
            return [[], $form];
        }

        $clientId = (string) $credentials->clientId;
        $secret   = $credentials->secret();

        return match ($credentials->kind) {
            CredentialKind::CLIENT_SECRET_BASIC => [['Authorization' => 'Basic ' . base64_encode(urlencode($clientId) . ':' . urlencode($secret))], $form],
            CredentialKind::CLIENT_SECRET_POST  => [[], [...$form, 'client_id' => $clientId, 'client_secret' => $secret]],
            CredentialKind::PRIVATE_KEY_JWT     => [[], [...$form, 'client_id' => $clientId, 'client_assertion_type' => self::ASSERTION_TYPE, 'client_assertion' => $secret]],
            CredentialKind::ACCESS_TOKEN        => [['Authorization' => 'Bearer ' . $secret], $form],
        };
    }

    /**
     * The response's headers, each by its name with its values joined.
     *
     * @param  \Psr\Http\Message\ResponseInterface  $response
     * @return array<string, string>
     */
    private static function headers(ResponseInterface $response): array
    {
        return array_map(static fn (array $values): string => implode(', ', $values), $response->getHeaders());
    }
}
