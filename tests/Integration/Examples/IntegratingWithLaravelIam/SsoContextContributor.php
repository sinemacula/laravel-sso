<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use SineMacula\Laravel\Authentication\Context\ContributionSubject;
use SineMacula\Laravel\Authentication\Contracts\AuthenticationContextContributor;
use SineMacula\Laravel\Sso\Sessions\AuthenticationContext;

/**
 * The adapter's `sso` authentication context contributor.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoContextContributor implements AuthenticationContextContributor
{
    // @snippet-start iam-context-contributor
    /**
     * The session's `sso` keys, without their prefix.
     *
     * @param  \SineMacula\Laravel\Authentication\Context\ContributionSubject  $subject
     * @return array<string, mixed>
     */
    #[\Override]
    public function contribute(ContributionSubject $subject): array
    {
        // Provenance::toArray(), passed as the provider context at sign-in
        // (PR #129); null for a session this package did not establish.
        $stored = $subject->provenance()?->providerContext?->toArray();

        $keys = [];

        foreach (AuthenticationContext::fromStored($stored) as $key => $value) {
            $keys[substr($key, strlen(AuthenticationContext::NAMESPACE) + 1)] = $value; // sso.connection -> connection
        }

        return $keys;
    }
    // @snippet-end iam-context-contributor
}
