<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Handoffs;

use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * A handoff issuer that records every grant it is given and issues a newly
 * generated code for each, expiring when the grant does, storing nothing. It
 * runs `onIssue` with the grant, if it is set, before it answers, and throws
 * the failure set instead of issuing, as an issuer that cannot store a code
 * does.
 *
 * A test binds the instance as `Contracts\HandoffIssuer`, so it reads the
 * grants and the codes issued.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class RecordingHandoffIssuer implements HandoffIssuer
{
    /** @var ?\Throwable What the issuer throws instead of issuing, when set. */
    public ?\Throwable $failure = null;

    /** @var ?\Closure(\SineMacula\Laravel\Sso\Handoffs\HandoffGrant): void What runs with each grant before the issuer answers. */
    public ?\Closure $onIssue = null;

    /** @var list<\SineMacula\Laravel\Sso\Handoffs\HandoffGrant> Every grant given, in order. */
    private array $grants = [];

    /** @var list<\SineMacula\Laravel\Sso\Handoffs\IssuedHandoff> Every handoff issued, in order. */
    private array $issued = [];

    /**
     * Record the grant, run `onIssue`, then throw the failure set or issue a
     * new code.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     *
     * @throws \Throwable
     */
    #[\Override]
    public function issue(HandoffGrant $grant): IssuedHandoff
    {
        $this->grants[] = $grant;

        if ($this->onIssue !== null) {
            ($this->onIssue)($grant);
        }

        if ($this->failure !== null) {
            throw $this->failure;
        }

        $issued = new IssuedHandoff(HandoffCode::generate(), $grant->expiresAt);

        $this->issued[] = $issued;

        return $issued;
    }

    /**
     * Every grant given, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Handoffs\HandoffGrant>
     */
    public function grants(): array
    {
        return $this->grants;
    }

    /**
     * Every handoff issued, in order.
     *
     * @return list<\SineMacula\Laravel\Sso\Handoffs\IssuedHandoff>
     */
    public function issued(): array
    {
        return $this->issued;
    }

    /**
     * The only grant given.
     *
     * @return \SineMacula\Laravel\Sso\Handoffs\HandoffGrant
     *
     * @throws \LogicException
     */
    public function soleGrant(): HandoffGrant
    {
        if (count($this->grants) !== 1) {
            throw new \LogicException(sprintf('The issuer was given %d grants, not one.', count($this->grants)));
        }

        return $this->grants[0];
    }
}
