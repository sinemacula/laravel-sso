<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[saml2]`: the caps and windows every SAML connection is held to, while the
 * `saml2` feature is on (SSO-6.1, SSO-6.5, SSO-12.3), each read as
 * `Saml2Limits` reads it, so the check and the flows judge it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Saml2Check implements ConfigurationCheck
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
     * The limits are checked while the `saml2` feature is on, or its switch is
     * malformed.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::requested(Feature::SAML2);
    }

    /**
     * Each cap, then the `IssueInstant` maximum age.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $limits = new Saml2Limits($this->config);

        return [
            static fn (): int => $limits->maxResponseBytes(),
            static fn (): int => $limits->maxXmlBytes(),
            static fn (): int => $limits->maxDecryptedBytes(),
            static fn (): int => $limits->issueInstantMaxAgeSeconds(),
        ];
    }
}
