<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use GuzzleHttp\Handler\CurlHandler;
use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\MissingExtensionException;

/**
 * Checks the `[fetcher]` settings through `FetcherSettings`, and that the cURL
 * transport the fetcher pins addresses with is available.
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
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \SineMacula\Laravel\Sso\Fetching\FetcherSettings  $settings
     * @param  ?\Closure(string): bool  $loaded
     * @param  ?\Closure(string): bool  $classExists
     */
    public function __construct(

        /** The configuration that says whether the package is in use. */
        private Repository $config,

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
     * Apply while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * Read each setting, then check the timeouts together and the transport.
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
     * Require the connect timeout to be no longer than the timeout; a malformed
     * one is left to its own check.
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
