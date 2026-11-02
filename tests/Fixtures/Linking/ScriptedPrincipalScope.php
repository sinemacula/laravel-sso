<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Linking;

use SineMacula\Laravel\Sso\Contracts\PrincipalScope;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict;

/**
 * A principal scope contract answering what the test sets, or throwing it, and
 * recording what it was asked.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedPrincipalScope implements PrincipalScope
{
    /** @var list<array{0: string, 1: string, 2: string}> Every question asked: the identity's type and id, and the tenant. */
    public array $asked = [];

    /** @var ?\Throwable What it throws instead of answering. */
    public ?\Throwable $failure = null;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict  $verdict
     */
    public function __construct(

        /** What it answers. */
        public ScopeVerdict $verdict = ScopeVerdict::WITHIN_TENANT,
    ) {}

    /**
     * Answer the verdict set.
     *
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $tenantId
     * @return \SineMacula\Laravel\Sso\Linking\Enums\ScopeVerdict
     *
     * @throws \Throwable
     */
    #[\Override]
    public function judge(IdentityReference $identity, string $tenantId): ScopeVerdict
    {
        $this->asked[] = [$identity->type, $identity->id, $tenantId];

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->verdict;
    }
}
