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
 * A fetcher that sends through the egress proxy in `services.egress.proxy` and
 * keeps the package fetcher's guarantees: https only, no redirects, the time
 * and size caps, refused addresses refused, and failures returned, not thrown.
 * Host names are resolved by the proxy, whose allow-list refuses the same
 * addresses.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProxiedFetcher implements Fetcher
{
    /** @var string The `client_assertion_type` of a signed client assertion (RFC 7523 section 2.2). */
    private const string ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

    /** @var string A last label a parser may read as an IPv4 address. */
    private const string NUMERIC_LAST_LABEL = '/(?:^|\.)(?:0x[0-9a-f]*|[0-9]+)$/iD';

    /** @var \GuzzleHttp\Client The client every request leaves through. */
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

        /** The addresses the package refuses. */
        private AddressPolicy $policy,

        // Not promoted: only passed to the handler stack; tests give one
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
     * Whether the URL is not `https`, has no host, carries user information or
     * a fragment, or names an IP address that is non-canonical or refused.
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
     * The Guzzle options: time cap, size-capped sink, credential and form.
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
     * The sink, throwing on a write past the cap to stop the transfer.
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
     * The headers and form with the credential placed as its kind says; Basic
     * credentials are form-encoded first (RFC 6749 section 2.3.1).
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
     * The response's headers, each with its values joined.
     *
     * @param  \Psr\Http\Message\ResponseInterface  $response
     * @return array<string, string>
     */
    private static function headers(ResponseInterface $response): array
    {
        return array_map(static fn (array $values): string => implode(', ', $values), $response->getHeaders());
    }
}
