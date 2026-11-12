<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion;

use Illuminate\Contracts\Container\Container;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;

/**
 * Offers a genuinely unlinked `sign_in` result to `ResultUnlinked` listeners,
 * with no package transaction open and a grant closed once they return.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class ProvisioningOffer
{
    /** @var string The container key of the grants the dispatches issued. */
    private const string DISPATCHES = 'sso.provisioning.dispatches';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Container\Container  $container
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionEvents  $events
     */
    public function __construct(

        /** Resolves the events dispatcher at each dispatch. */
        private Container $container,

        /** Builds the event's context. */
        private CompletionEvents $events,
    ) {}

    /**
     * Dispatch the unlinked-result event with its grant; a listener that leaves
     * a transaction open is rolled back and refused.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return void
     *
     * @throws \LogicException
     */
    public function dispatch(CompletionState $state): void
    {
        $result   = $state->result               ?? throw new \LogicException('A result is offered for provisioning once it is verified.');
        $request  = $state->authorizationRequest ?? throw new \LogicException('A result is offered for provisioning once its request is consumed.');
        $until    = $state->verifiedUntil        ?? throw new \LogicException('A result is offered for provisioning with its deadline.');
        $grant    = ProvisioningGrant::issue($result, $request->id, $until, $state->transitionReceipt);
        $database = DB::connection(StorageConnection::name());
        $level    = $database->transactionLevel();

        $this->dispatches()->offsetSet($grant, $request->id);

        try {
            $this->container->make(Dispatcher::class)->dispatch(new ResultUnlinked($this->events->context($state), $result, $grant));
        } finally {
            $grant->close();

            $left = $database->transactionLevel() > $level;

            if ($left) {
                $database->rollBack($level);
            }
        }

        if ($left) {
            throw new \LogicException('A provisioning listener must commit or roll back its transaction before it returns (SSO-8.6).');
        }
    }

    /**
     * Whether a dispatch issued the grant.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return bool
     */
    public function isRegistered(ProvisioningGrant $grant): bool
    {
        return $this->dispatches()->offsetExists($grant);
    }

    /**
     * The grants the dispatches issued, by request id, held weakly.
     *
     * @return \WeakMap<\SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant, string>
     */
    private function dispatches(): \WeakMap
    {
        if (!$this->container->bound(self::DISPATCHES)) {
            $this->container->instance(self::DISPATCHES, new \WeakMap);
        }

        /** @var \WeakMap<\SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant, string> */
        return $this->container->make(self::DISPATCHES);
    }
}
