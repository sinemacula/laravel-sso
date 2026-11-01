<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Enforcement;

use SineMacula\Laravel\Sso\Contracts\EnforcementInheritance;

/**
 * An enforcement inheritance contract that answers from a script: the answers
 * given, one per call in order, the last repeated once the script runs out, so
 * a test can move a tenant to another enforcing tenant between two questions.
 * It records each tenant and application asked about.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ScriptedInheritance implements EnforcementInheritance
{
    /** @var list<array{0: string, 1: string}> Each tenant and application asked about, in order. */
    private array $asked = [];

    /**
     * Constructor.
     *
     * @param  non-empty-list<string>  $answers
     */
    public function __construct(

        /** The enforcing tenant each call answers, in order, the last repeated. */
        private readonly array $answers,
    ) {}

    /**
     * The next answer of the script.
     *
     * @param  string  $tenantId
     * @param  string  $application
     * @return string
     */
    #[\Override]
    public function enforcingTenant(string $tenantId, string $application): string
    {
        $this->asked[] = [$tenantId, $application];

        return $this->answers[min(count($this->asked), count($this->answers)) - 1];
    }

    /**
     * Each tenant and application asked about, in order.
     *
     * @return list<array{0: string, 1: string}>
     */
    public function asked(): array
    {
        return $this->asked;
    }
}
