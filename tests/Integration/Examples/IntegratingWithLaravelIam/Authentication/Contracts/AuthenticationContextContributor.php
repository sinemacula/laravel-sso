<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Contracts;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;

/**
 * A stand-in for `laravel-authentication`'s
 * `Contracts\AuthenticationContextContributor`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface AuthenticationContextContributor
{
    /**
     * The keys to add, by name without the namespace.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     */
    public function contribute(ContributionSubject $subject): array;
}
