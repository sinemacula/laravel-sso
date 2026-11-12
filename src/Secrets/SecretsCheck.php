<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Secrets;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Container\Container;
use Illuminate\Encryption\MissingAppKeyException;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;

/**
 * `[secrets]`: checks the bound secret encrypter resolves and, if it is the
 * default, works.
 *
 * A custom encrypter is never called, so the check makes no network request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SecretsCheck implements ConfigurationCheck
{
    /** @var string What the default encrypter is asked to round-trip. */
    private const string PROBE = 'sso-secrets-check';

    /** @var string The problem of a default encrypter that cannot work. */
    private const string UNUSABLE = 'The default secret encrypter cannot encrypt and decrypt with `app.key`; set APP_KEY, or bind your own SecretEncrypter.';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  \Illuminate\Contracts\Container\Container  $container
     */
    public function __construct(

        /** The configuration that says whether the package is in use. */
        private Repository $config,

        /** The container the encrypter is resolved from. */
        private Container $container,
    ) {}

    /**
     * Secrets are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * That the encrypter resolves and, when it is the default, works.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            function (): void {
                $this->assertUsable();
            },
        ];
    }

    /**
     * Resolve the bound encrypter and, if it is the default, round-trip a
     * probe.
     *
     * @return void
     *
     * @throws \LogicException
     * @throws \Throwable
     */
    private function assertUsable(): void
    {
        try {
            $encrypter = $this->container->make(SecretEncrypter::class);
        } catch (\Throwable $exception) {
            if ($exception instanceof MissingAppKeyException) {
                throw new \LogicException(self::UNUSABLE, 0, $exception);
            }

            throw $exception;
        }

        if (!$encrypter instanceof LaravelSecretEncrypter) {
            return;
        }

        try {
            $works = $encrypter->decrypt($encrypter->encrypt(self::PROBE)) === self::PROBE;
        } catch (\RuntimeException) {
            $works = false;
        }

        if (!$works) {
            throw new \LogicException(self::UNUSABLE);
        }
    }
}
