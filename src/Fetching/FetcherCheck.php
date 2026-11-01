<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use GuzzleHttp\Handler\CurlHandler;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\MissingExtensionException;

/**
 * `[fetcher]`: the outbound fetcher's settings and its transport, while the
 * package is in use (SSO-2.9). Each setting is read as `FetcherSettings` reads
 * it, so the check and the fetcher judge it the same way; the connect timeout
 * must not exceed the timeout; and `ext-curl` must be loaded with Guzzle's cURL
 * handler available, since the fetcher pins the address it checked with
 * `CURLOPT_RESOLVE` and never falls back to PHP streams.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FetcherCheck implements ConfigurationCheck
{
    /** @var string The problem of a missing cURL transport. */
    public const string NO_CURL = 'The PHP extension `curl` and Guzzle\'s cURL handler are needed by the outbound fetcher,'
        . ' which pins the address it checked with CURLOPT_RESOLVE and never falls back to PHP streams.';

    /** @var \Closure(string): bool Whether an extension is loaded. */
    private \Closure $loaded;

    /** @var \Closure(string): bool Whether a class exists. */
    private \Closure $classExists;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     * @param  ?\Closure(string): bool  $loaded
     * @param  ?\Closure(string): bool  $classExists
     */
    public function __construct(

        /** The settings checked. */
        private FetcherSettings $settings,

        // Not promoted: `extension_loaded()` stands in when none is given
        ?\Closure $loaded = null,

        // Not promoted: `class_exists()` stands in when none is given
        ?\Closure $classExists = null,
    ) {
        $this->loaded      = $loaded      ?? extension_loaded(...);
        $this->classExists = $classExists ?? class_exists(...);
    }

    /**
     * The fetcher is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * Each setting, the two timeouts together, and the cURL transport.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            fn (): int => $this->settings->timeoutSeconds(),
            fn (): int => $this->settings->connectTimeoutSeconds(),
            fn (): int => $this->settings->maxResponseBytes(),
            fn (): int => $this->settings->maxRedirects(),
            fn (): array => $this->settings->refusedRanges(),
            function (): void {
                $this->assertConnectTimeoutWithinTimeout();
            },
            function (): void {
                if (!($this->loaded)('curl') || !($this->classExists)(CurlHandler::class)) {
                    throw new MissingExtensionException(self::NO_CURL);
                }
            },
        ];
    }

    /**
     * Require the connect timeout to be no longer than the timeout, once both
     * are well formed: a malformed one is reported by its own check.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function assertConnectTimeoutWithinTimeout(): void
    {
        try {
            $timeout = $this->settings->timeoutSeconds();
            $connect = $this->settings->connectTimeoutSeconds();
        } catch (\InvalidArgumentException) {
            return;
        }

        if ($connect > $timeout) {
            throw new \InvalidArgumentException(FetcherSettings::CONNECT_TIMEOUT_EXCEEDS_TIMEOUT);
        }
    }
}
