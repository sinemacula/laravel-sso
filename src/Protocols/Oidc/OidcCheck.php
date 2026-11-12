<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * Checks the `[oidc]` limits through `OidcLimits`, so the check and the flows
 * read them the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class OidcCheck implements ConfigurationCheck
{
    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * Apply while the `oidc` feature is on or its switch is malformed.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::requested($this->config, Feature::OIDC);
    }

    /**
     * Read each cap, window and timeout.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $limits = new OidcLimits($this->config);

        return [
            static fn (): int => $limits->maxIdTokenBytes(),
            static fn (): int => $limits->maxJwksBytes(),
            static fn (): int => $limits->maxJwksKeys(),
            static fn (): int => $limits->maxDiscoveryBytes(),
            static fn (): int => $limits->maxTokenResponseBytes(),
            static fn (): int => $limits->maxUserInfoBytes(),
            static fn (): int => $limits->maxCallbackParameterBytes(),
            static fn (): int => $limits->maxCallbackQueryBytes(),
            static fn (): int => $limits->maxCallbackParameters(),
            static fn (): int => $limits->jwksRefetchCooldownSeconds(),
            static fn (): int => $limits->idTokenMaxAgeSeconds(),
            static fn (): int => $limits->tokenTimeoutSeconds(),
            static fn (): int => $limits->userInfoTimeoutSeconds(),
        ];
    }
}
