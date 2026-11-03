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
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode as StoredCode;

/**
 * Reports how a redemption through the package's own redemption helper ended
 * (SSO-10.1, SSO-10.2, SSO-10.4), once per redemption: `HandoffRedeemed` for a
 * code redeemed, and exactly one `FlowFailed` (`Flow::REDEMPTION`) with its
 * reason for a refused one, a full limit included.
 *
 * Each event's context is built through the one projection
 * (`Events\EventContexts`) from what the redemption had established. Before a
 * stored code was found, it names only the purpose the application asked to
 * redeem. Once found, it names the code's connection, application, purpose and
 * request's public reference, the identity it concerns (the one a `link` or a
 * `reauthenticate` flow was started for, and otherwise the one the result's
 * link resolved to at completion), and the session a `reauthenticate` flow was
 * started on; once the connection's row was read, its tenant and protocol too.
 * The public reference is the only flow identifier it carries (SSO-9.8); never
 * the code, its digest, the verifier, the challenge, the subject or an
 * attribute (SSO-10.4).
 *
 * Each event is handed to `Events\AfterCommitDispatcher`: reported inside the
 * redemption's transaction, it reaches listeners once that commits, and never
 * when it, or the caller's transaction around it, rolls back (SSO-10.5).
 *
 * It holds the projection and the dispatcher, both of which read the clock, the
 * request and the transaction from the container on each call, so nothing of
 * one redemption is kept for the next (SSO-11.2).
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
     * Report the code redeemed through the connection. Called inside the
     * transaction that consumed it, after the write.
     *
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function redeemed(StoredCode $code, Connection $connection, ?IdentityReference $identity = null): void
    {
        $context = $this->context($code->purpose, $code, $connection, $identity);

        $this->dispatcher->dispatch(new HandoffRedeemed($context));

        if ($code->purpose !== Purpose::REAUTHENTICATE) {
            return;
        }

        $this->dispatcher->dispatch(new ReauthenticationCompleted($context));
    }

    /**
     * Report a redemption refused for the reason before any stored code was
     * found, for the purpose the application asked to redeem.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function refused(FailureReason $reason, Purpose $purpose): void
    {
        $this->dispatcher->dispatch(new FlowFailed($this->context($purpose), Flow::REDEMPTION, $reason));
    }

    /**
     * Report a redemption of the stored code refused for the reason, with its
     * connection once its row was read.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  \SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function failed(FailureReason $reason, StoredCode $code, ?Connection $connection = null): void
    {
        $this->dispatcher->dispatch(new FlowFailed($this->context($code->purpose, $code, $connection), Flow::REDEMPTION, $reason));
    }

    /**
     * The context of the redemption, with what it had established.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  ?\SineMacula\Laravel\Sso\Models\HandoffCode  $code
     * @param  ?\SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $established
     * @return \SineMacula\Laravel\Sso\Events\EventContext
     *
     * @throws \InvalidArgumentException
     */
    private function context(Purpose $purpose, ?StoredCode $code = null, ?Connection $connection = null, ?IdentityReference $established = null): EventContext
    {
        $identity = $established ?? self::identity($code);

        return $this->contexts->make(
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
     * The identity the code concerns: the one a `link` or a `reauthenticate`
     * flow was started for, and otherwise the one the result's link resolved to
     * at completion; none when it names neither, or no code was found.
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
