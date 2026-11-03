<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[mapping]`: the caps on what an attribute mapping carries and the custom
 * keys the application declares, while the package is in use (SSO-2.10), each
 * read as `MappingLimits` reads it, so the check and the mapping judge it the
 * same way.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class MappingCheck implements ConfigurationCheck
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
     * The mapping is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The two caps and the declared custom keys.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $limits = new MappingLimits($this->config);

        return [
            static fn (): int => $limits->maxValueLength(),
            static fn (): int => $limits->maxValues(),
            static fn (): array => $limits->customAttributes(),
        ];
    }
}
