<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Sessions\Provenance;

/**
 * Redeems codes the application's own store issued, through `HandoffRecheck`; a
 * refusal commits, and spends the code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnHandoffRedemption
{
    /**
     * Redeem the application's own codes and write the sessions they establish.
     *
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCodes  $codes
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\SignIns  $signIns
     */
    public function __construct(

        /** The application's own store of codes. */
        private OwnHandoffCodes $codes,

        /** The application's own sessions. */
        private SignIns $signIns,
    ) {}

    /**
     * Redeem the code, answering `null` when admitted or the refusal reason.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $value
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    public function redeem(
        Purpose $purpose,
        #[\SensitiveParameter] string $value,
        #[\SensitiveParameter] string $verifier,
        ClientContext $client,
        ?Caller $caller = null,
    ): ?FailureReason {
        $code = $this->codes->find($value);

        return $code === null ? FailureReason::HANDOFF_UNKNOWN : $this->admit($code, $purpose, $verifier, $client, $caller);
    }

    /**
     * Lock, consume, check and admit the code in one transaction on the
     * package's storage connection.
     *
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $verifier
     * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function admit(OwnHandoffCode $code, Purpose $purpose, #[\SensitiveParameter] string $verifier, ClientContext $client, ?Caller $caller): ?FailureReason
    {
        // @snippet-start own-code-redemption
        return DB::connection(StorageConnection::name())->transaction(function () use ($code, $purpose, $verifier, $client, $caller): ?FailureReason {
            $result = $code->result;

            // The lock comes first, before your code is locked
            $recheck = app(HandoffRecheck::class);
            $lock    = $recheck->lock(
                $result->tenantId,
                $result->connectionId,
                $result->application,
                $code->reservationId,                                        // the reservation it holds, if any
                $result->purpose === Purpose::LINK ? $code->identity : null, // the identity of a `link` flow
            );

            // Your own atomic, single-use consumption, locked after, through
            // this same connection, with your own checks: a replay, the expiry,
            // the purpose your endpoint redeems and the verifier
            $refusal = $this->codes->consume($code, $purpose, $verifier);

            $binding = new HandoffBinding(
                linkedIdentity: $code->linkedIdentity, // the identity the result's link resolved to, if any
                linkId: $code->linkId,                 // the link observed at completion, active or suspended, if any
                identity: $code->identity,             // the identity of a `link` or `reauthenticate` flow
                sessionId: $code->sessionId,           // the session of a `reauthenticate` flow
                reservationId: $code->reservationId,   // the reservation it holds, if any
                handoffReference: $code->reference,    // the opaque reference your issuer answered
                trustVersion: $code->trustVersion,     // the connection's trust version it was issued under
            );

            $admission = $refusal === null ? $recheck->admit($result, $binding, $lock, $client, $caller) : null;

            if ($admission === null || !$admission->isPassed()) {
                $recheck->discardReservation($binding, $result->connectionId);

                return $refusal ?? $admission?->outcome->reason(); // refuse; your code stays consumed
            }

            if ($result->purpose === Purpose::SIGN_IN && $admission->identity !== null) {
                $recheck->acknowledgeSignIn($result, $lock);

                // Write the session for the identity, bound to the link it
                // resolved through, never outliving the latest end your issuer
                // stored, with how it began, in this same transaction
                $this->signIns->start(
                    $admission->identity,
                    (string) $admission->linkId,
                    $code->sessionNotAfter,
                    Provenance::capture($result, $admission, $code->sessionNotAfter),
                );
            }

            // A `link` writes nothing further; a `reauthenticate` was renewed
            // by the admission
            return null;
        });
        // @snippet-end own-code-redemption
    }
}
