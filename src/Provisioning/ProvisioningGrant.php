<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The single use of the provisioning helper an unlinked `sign_in` result is
 * offered (SSO-8.6), for the listeners of `Events\ResultUnlinked`.
 *
 * Only the completion issues one, and registers it to the active dispatch
 * (`Completion\ProvisioningOffer`), so a grant issued anywhere else opens
 * nothing. It is bound to the exact immutable result object, which names its
 * tenant, application and purpose, so it can never be reconstructed from public
 * constructor arguments nor used for another result. `claim()` marks it used
 * before the helper attempts anything, whatever it was presented with, so
 * reentrant calls or a second listener get no second use, and a refused claim
 * or attempt spends it for good, so it cannot be reused for another identity.
 * `close()` runs in the dispatch's `finally`, so it is void once the dispatch
 * returns, or throws.
 *
 * A claim is released, for the same dispatch to claim again, only on evidence
 * that the attempt which made it rolled back as a whole: the helper binds it
 * (`bind()`) to the outermost transaction open on the storage connection whose
 * callbacks apply, which is the helper's own when the listener has none (the
 * testing traits' wrapping transaction is not one), and that transaction's
 * rollback callback marks it. It is claimable again once marked and its
 * transaction is gone from the manager; a commit, a rolled-back savepoint
 * inside it, a commit Laravel 12 fails to report, or a claim never bound leaves
 * it used. So a listener can retry its whole transaction after a deadlock.
 *
 * It proves the authority to provision for this result, not when an application
 * identity was created: that the identity is new remains the adapter's
 * obligation (`docs/design/linking.md`).
 *
 * It holds the result, so it cannot be cloned or (un)serialised; a dump and
 * `json_encode()` show only whether it is still usable; and the result, the
 * request's id and the response's receipt are held wrapped, so `var_export()`
 * and an array cast, which no `__debugInfo()` governs, show none of them.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class ProvisioningGrant implements \JsonSerializable
{
    /** @var bool Whether its dispatch is still running. */
    private bool $open = true;

    /** @var bool Whether a claim holds the grant's one use. */
    private bool $used = false;

    /** @var bool Whether a claim or an attempt was refused, which spends it for good. */
    private bool $refused = false;

    /** @var ?\Illuminate\Database\DatabaseTransactionsManager The manager of the transaction the claim is bound to. */
    private ?DatabaseTransactionsManager $manager = null;

    /** @var ?\Illuminate\Database\DatabaseTransactionRecord The outermost transaction the claim runs in, once bound. */
    private ?DatabaseTransactionRecord $root = null;

    /** @var bool Whether the transaction the claim is bound to was rolled back. */
    private bool $rolledBack = false;

    /**
     * Constructor.
     *
     * @param  \SensitiveParameterValue  $result
     * @param  \SensitiveParameterValue  $requestId
     * @param  \Carbon\CarbonImmutable  $verifiedUntil
     * @param  \SensitiveParameterValue  $receipt
     */
    private function __construct(

        /** The exact result the grant is bound to, held wrapped. */
        private readonly \SensitiveParameterValue $result,

        /** The consumed, unfinished request the result answers, held wrapped. */
        private readonly \SensitiveParameterValue $requestId,

        /** The end of the verified response's validity, which no continuation extends. */
        private readonly CarbonImmutable $verifiedUntil,

        /** What lets the request finish across its response's own key rotation, held wrapped. */
        private readonly \SensitiveParameterValue $receipt,
    ) {}

    /**
     * Refuse to be cloned: a clone would be a second use.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function __clone(): void
    {
        throw new \LogicException('A provisioning grant cannot be cloned.');
    }

    /**
     * What a dump shows: whether it is still usable, never the result.
     *
     * @return array<string, bool>
     */
    public function __debugInfo(): array
    {
        return $this->jsonSerialize();
    }

    /**
     * Refuse to be serialised: it is valid only during its dispatch.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A provisioning grant cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A provisioning grant cannot be unserialised.');
    }

    /**
     * Issue the grant of a dispatch about to run. Only the completion calls it,
     * and registers what it answers.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @param  string  $requestId
     * @param  \Carbon\CarbonImmutable  $verifiedUntil
     * @param  ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt  $receipt
     * @return self
     *
     * @internal
     */
    public static function issue(#[\SensitiveParameter] VerifiedResult $result, string $requestId, CarbonImmutable $verifiedUntil, ?TransitionReceipt $receipt = null): self
    {
        return new self(new \SensitiveParameterValue($result), new \SensitiveParameterValue($requestId), $verifiedUntil, new \SensitiveParameterValue($receipt));
    }

    /**
     * Claim the grant's one use for the exact result, while its dispatch runs:
     * any claim marks it used, before anything is attempted, and only the
     * first, of the result it is bound to, answers the consumed, unfinished
     * request the helper checks under its locks, as does a claim again once the
     * first's transaction rolled back; every other answers `null`, and spends
     * the grant for good.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return ?string
     */
    public function claim(#[\SensitiveParameter] VerifiedResult $result): ?string
    {
        if (!$this->isUsable() || !$this->isBoundTo($result)) {
            $this->refused = true;

            return null;
        }

        $this->used       = true;
        $this->root       = null;
        $this->rolledBack = false;

        /** @var string */
        return $this->requestId->getValue();
    }

    /**
     * Bind the claim to the outermost transaction open on the connection whose
     * callbacks apply, so its rollback, and nothing else, releases the claim. A
     * claim already bound, or with no such transaction open, is left as it is.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @param  string  $connection
     * @return void
     *
     * @internal
     */
    public function bind(DatabaseTransactionsManager $manager, string $connection): void
    {
        if ($this->root !== null) {
            return;
        }

        $root = self::outermost($manager, $connection);

        if ($root === null) {
            return;
        }

        $this->manager = $manager;
        $this->root    = $root;

        $root->addCallbackForRollback(function () use ($root): void {

            if ($this->root !== $root) {
                return;
            }

            $this->rolledBack = true;
        });
    }

    /**
     * Spend the grant for good: the helper refused the attempt.
     *
     * @return void
     *
     * @internal
     */
    public function refuse(): void
    {
        $this->refused = true;
    }

    /**
     * Whether the grant is bound to exactly this result object. It claims
     * nothing.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return bool
     */
    public function isBoundTo(#[\SensitiveParameter] VerifiedResult $result): bool
    {
        return $this->result->getValue() === $result;
    }

    /**
     * Void the grant, whatever its dispatch came to.
     *
     * @return void
     */
    public function close(): void
    {
        $this->open = false;
    }

    /**
     * Whether its dispatch is running, nothing refused it, and its one use is
     * unclaimed or released by the rollback of the claim's transaction.
     *
     * @return bool
     */
    public function isUsable(): bool
    {
        return $this->open && !$this->refused && (!$this->used || $this->isReleased());
    }

    /**
     * The end of the verified response's validity, checked before the helper's
     * write.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function verifiedUntil(): CarbonImmutable
    {
        return $this->verifiedUntil;
    }

    /**
     * The receipt of the key rotation the response's own validation made, if
     * any, which the helper judges under its locks.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt
     */
    public function transitionReceipt(): ?TransitionReceipt
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt */
        return $this->receipt->getValue();
    }

    /**
     * What `json_encode()` writes: whether it is still usable.
     *
     * @return array<string, bool>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['usable' => $this->isUsable()];
    }

    /**
     * The outermost record, of those the manager holds open on the connection
     * whose callbacks apply, that the innermost one is in.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @param  string  $connection
     * @return ?\Illuminate\Database\DatabaseTransactionRecord
     */
    private static function outermost(DatabaseTransactionsManager $manager, string $connection): ?DatabaseTransactionRecord
    {
        $applicable = $manager->callbackApplicableTransactions();
        $current    = $applicable->last(static fn (DatabaseTransactionRecord $record): bool => $record->connection === $connection);
        $outermost  = null;

        while ($current !== null && $applicable->containsStrict($current)) {
            $outermost = $current;
            $current   = $current->parent;
        }

        return $outermost;
    }

    /**
     * Whether the claim's transaction was rolled back and its manager no longer
     * holds it. Its disappearance alone proves nothing: a commit removes it
     * before running its callbacks.
     *
     * @return bool
     */
    private function isReleased(): bool
    {
        $manager = $this->manager;
        $root    = $this->root;

        if (!$this->rolledBack || $manager === null) {
            return false;
        }

        $held = $manager->getPendingTransactions()->concat($manager->getCommittedTransactions());

        return !$held->contains(static fn (DatabaseTransactionRecord $record): bool => $record === $root);
    }
}
