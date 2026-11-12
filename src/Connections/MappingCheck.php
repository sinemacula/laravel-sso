<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * Checks the attribute mapping caps and custom keys, read through
 * `MappingLimits` so the check and the mapping agree.
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
     * Applies while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
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
