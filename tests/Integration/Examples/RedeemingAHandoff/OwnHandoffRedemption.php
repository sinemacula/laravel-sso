<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\HandoffRecheck;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * The redemption of an application's own handoff codes of
 * `docs/guides/redeeming-a-handoff.md` (SSO-4.6, SSO-8.5, SSO-8.8, SSO-9.9,
 * SSO-12.5), for codes its own store issued: it reads the code plainly to learn
 * the result it carries, then, in one transaction on the package's storage
 * connection, takes `HandoffRecheck`'s lock first, consumes and checks its own
 * code after it, describes what the code was bound to with a `HandoffBinding`,
 * and admits it, discarding the reservation of every refusal and writing the
 * session of an admitted `sign_in` in that same transaction.
 *
 * It answers `null` when the code is admitted, or the reason it is refused; a
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
     * Redeem the code for the purpose the endpoint redeems, with the client's
     * verifier and the caller the application authenticated, which a `link`
     * needs.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $value
     * @param  string  $verifier
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    public function redeem(Purpose $purpose, #[\SensitiveParameter] string $value, #[\SensitiveParameter] string $verifier, ?IdentityReference $caller = null): ?FailureReason
    {
        // Read the code plainly first, to learn the result it carries
        $code = $this->codes->find($value);

        return $code === null ? FailureReason::HANDOFF_UNKNOWN : $this->admit($code, $purpose, $verifier, $caller);
    }

    /**
     * Lock, consume, check and admit the code in one transaction on the
     * package's storage connection.
     *
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $verifier
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     *
     * @throws \Throwable
     */
    private function admit(OwnHandoffCode $code, Purpose $purpose, #[\SensitiveParameter] string $verifier, ?IdentityReference $caller): ?FailureReason
    {
        // @snippet-start own-code-redemption
        return DB::connection(StorageConnection::name())->transaction(function () use ($code, $purpose, $verifier, $caller): ?FailureReason {
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
            );

            $admission = $refusal === null ? $recheck->admit($result, $binding, $lock, $caller) : null;

            if ($admission === null || !$admission->isPassed()) {
                $recheck->discardReservation($binding, $result->connectionId);

                return $refusal ?? $admission?->outcome->reason(); // refuse; your code stays consumed
            }

            if ($result->purpose === Purpose::SIGN_IN && $admission->identity !== null) {
                $recheck->acknowledgeSignIn($result, $lock);

                // Write the session for the identity, bound to the link it
                // resolved through, in this same transaction
                $this->signIns->start($admission->identity, (string) $admission->linkId);
            }

            // A `link` writes nothing further; a `reauthenticate` was renewed
            // by the admission
            return null;
        });
        // @snippet-end own-code-redemption
    }
}
