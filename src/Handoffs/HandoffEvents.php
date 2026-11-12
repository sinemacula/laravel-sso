<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs;

use SineMacula\Laravel\Sso\Events\AfterCommitDispatcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Events\Enums\Flow;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\EventContexts;
use SineMacula\Laravel\Sso\Events\FlowFailed;
use SineMacula\Laravel\Sso\Events\HandoffRedeemed;
use SineMacula\Laravel\Sso\Events\ReauthenticationCompleted;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;

/**
 * Reports how a redemption ended, once, after its transaction commits.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class HandoffEvents
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\EventContexts  $contexts
     * @param  \SineMacula\Laravel\Sso\Events\AfterCommitDispatcher  $dispatcher
     */
    public function __construct(

        /** The projection every event's context is built through. */
        private EventContexts $contexts,

        /** The dispatcher that waits for the redemption to commit. */
        private AfterCommitDispatcher $dispatcher,
    ) {}

    /**
     * Report the code redeemed, from inside the transaction that consumed it.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function redeemed(StoredCode $code, Connection $connection, ClientContext $client, ?IdentityReference $identity = null): void
    {
        $context = $this->context($code->purpose, $client, $code, $connection, $identity);

        $this->dispatcher->dispatch(new HandoffRedeemed($context));

        if ($code->purpose !== Purpose::REAUTHENTICATE) {
            return;
        }

        $this->dispatcher->dispatch(new ReauthenticationCompleted($context));
    }

    /**
     * Report a redemption refused before any stored code was found.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refused(FailureReason $reason, Purpose $purpose, ClientContext $client): void
    {
        $this->dispatcher->dispatch(new FlowFailed($this->context($purpose, $client), Flow::REDEMPTION, $reason));
    }

    /**
     * Report a redemption of the stored code refused.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function failed(FailureReason $reason, StoredCode $code, ClientContext $client, ?Connection $connection = null): void
    {
        $this->dispatcher->dispatch(new FlowFailed($this->context($code->purpose, $client, $code, $connection), Flow::REDEMPTION, $reason));
    }

    /**
     * The event context of what the redemption had established.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $established
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     *
     * @throws \InvalidArgumentException
     */
    private function context(
        Purpose $purpose,
        ClientContext $client,
        ?StoredCode $code = null,
        ?Connection $connection = null,
        ?IdentityReference $established = null,
    ): EventContext {
        $identity = $established ?? self::identity($code);

        return $this->contexts->make(
            $client,
            connectionId: $code?->connection_id,
            connectionTenantId: $connection?->tenant_id,
            protocol: $connection?->protocol,
            application: $code?->application,
            purpose: $purpose->value,
            requestReference: $code?->request_reference,
            identityMorphClass: $identity?->type,
            identityId: $identity?->id,
            sessionId: $code?->session_id,
        );
    }

    /**
     * The identity the flow was started for, else the one its link resolved to.
     *
     * @param  ?\SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @return ?\SineMacula\Laravel\Sso\Identities\IdentityReference
     *
     * @throws \InvalidArgumentException
     */
    private static function identity(?StoredCode $code): ?IdentityReference
    {
        return IdentityReference::fromColumns($code?->identity_type, $code?->identity_id)
            ?? IdentityReference::fromColumns($code?->linked_identity_type, $code?->linked_identity_id);
    }
}
