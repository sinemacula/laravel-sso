<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\External;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;

/**
 * A stand-in for `laravel-authentication`'s `External\ExternalEvidence`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ExternalEvidence
{
    /** @var \Carbon\CarbonImmutable When the provider authenticated the identity, to the second. */
    public CarbonImmutable $authenticatedAt;

    /**
     * Constructor.
     *
     * @param  list<string>  $methods
     * @param  ?string  $context
     * @param  \Carbon\CarbonInterface  $authenticatedAt
     */
    public function __construct(

        /** The methods the provider stated. */
        public array $methods,

        /** The context class the provider stated, if any. */
        public ?string $context,

        // When the provider authenticated the identity
        CarbonInterface $authenticatedAt,
    ) {
        $this->authenticatedAt = CarbonImmutable::instance($authenticatedAt)->startOfSecond();
    }
}
