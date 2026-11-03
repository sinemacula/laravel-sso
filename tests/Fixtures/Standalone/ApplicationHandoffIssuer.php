<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Standalone;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;

/**
 * An application's handoff issuer: a wrapper of the package's store, which
 * writes the code inside the completion's transaction and answers its reference
 * and stored expiry, so a reservation stays bound to it. It records each grant
 * and the transaction level it was asked at.
 *
 * A test sets `failure` to have it throw once the code is written, as an issuer
 * that fails part way does, and `dropsReference` to have it answer no
 * reference, as an issuer that cannot hold a reservation does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ApplicationHandoffIssuer implements HandoffIssuer
{
    /** @var ?\Throwable What it throws once the code is written. */
    public ?\Throwable $failure = null;

    /** @var bool Whether it answers no reference. */
    public bool $dropsReference = false;

    /** @var list<\SineMacula\Laravel\Sso\Handoffs\HandoffGrant> Every grant given, in order. */
    public array $grants = [];

    /** @var list<int> The storage connection's transaction level at each grant. */
    public array $levels = [];

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\HandoffIssuer  $store
     */
    public function __construct(

        /** What writes the code. */
        private readonly HandoffIssuer $store,
    ) {}

    /**
     * Record the grant, have the store write its code, then throw the failure
     * set or answer what was written.
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
        $this->levels[] = DB::connection(StorageConnection::name())->transactionLevel();

        $issued = $this->store->issue($grant);

        if ($this->failure !== null) {
            throw $this->failure;
        }

        return $this->dropsReference ? new IssuedHandoff($issued->code, $issued->expiresAt) : $issued;
    }
}
