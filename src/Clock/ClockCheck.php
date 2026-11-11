<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Clock;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[clock]`: the clock skew every protocol time check allows, while the package
 * is in use (SSO-6.5, SSO-11.13). It must be an integer from 0 to 300 seconds,
 * read as `ClockSkew::seconds()` reads it, so the check and the time checks
 * judge it the same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ClockCheck implements ConfigurationCheck
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
     * The clock is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * The clock skew.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        return [
            static fn (): int => ClockSkew::seconds(),
        ];
    }
}
