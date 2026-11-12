<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * The single use of the provisioning helper offered to an unlinked `sign_in`
 * result, bound to that exact result object for one dispatch.
 *
 * A claim is released only when its whole outermost transaction rolled back, so
 * a listener can retry that transaction after a deadlock.
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

    /** @var bool Whether a claim or attempt was refused, spending it for good. */
    private bool $refused = false;

    /** @var ?\Illuminate\Database\DatabaseTransactionsManager The manager of the claim's transaction. */
    private ?DatabaseTransactionsManager $manager = null;

    /** @var ?\Illuminate\Database\DatabaseTransactionRecord The outermost transaction the claim is bound to. */
    private ?DatabaseTransactionRecord $root = null;

    /** @var bool Whether the claim's transaction was rolled back. */
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

        /** The exact result the grant is bound to. */
        private readonly \SensitiveParameterValue $result,

        /** The consumed, unfinished request the result answers. */
        private readonly \SensitiveParameterValue $requestId,

        /** The end of the verified response's validity; nothing extends it. */
        private readonly CarbonImmutable $verifiedUntil,

        /** Lets the request finish across its response's own key rotation. */
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
     * A dump shows only whether it is usable.
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
     * Issue the grant of a dispatch about to run; only the completion calls it.
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
     * Claim the one use and return the request id; any refused claim returns
     * `null` and spends the grant for good.
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
     * Bind an unbound claim to the outermost callback-applicable transaction,
     * whose rollback alone releases it.
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
     * Whether the grant is bound to exactly this result object.
     *
     * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
     * @return bool
     */
    public function isBoundTo(#[\SensitiveParameter] VerifiedResult $result): bool
    {
        return $this->result->getValue() === $result;
    }

    /**
     * Void the grant; called in the dispatch's `finally`.
     *
     * @return void
     */
    public function close(): void
    {
        $this->open = false;
    }

    /**
     * Whether the dispatch is open, nothing refused it, and its use is free.
     *
     * @return bool
     */
    public function isUsable(): bool
    {
        return $this->open && !$this->refused && (!$this->used || $this->isReleased());
    }

    /**
     * The end of the verified response's validity.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function verifiedUntil(): CarbonImmutable
    {
        return $this->verifiedUntil;
    }

    /**
     * The receipt of any key rotation the response's validation made.
     *
     * @return ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt
     */
    public function transitionReceipt(): ?TransitionReceipt
    {
        /** @var ?\SineMacula\Laravel\Sso\Protocols\TransitionReceipt */
        return $this->receipt->getValue();
    }

    /**
     * Only whether it is still usable.
     *
     * @return array<string, bool>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['usable' => $this->isUsable()];
    }

    /**
     * The outermost callback-applicable record enclosing the innermost one on
     * the connection, stepping only to strictly lower levels.
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

        // A parent no lower than its child was left by a failed commit.
        while ($current !== null && $applicable->containsStrict($current) && ($outermost === null || $current->level < $outermost->level)) {
            $outermost = $current;
            $current   = $current->parent;
        }

        return $outermost;
    }

    /**
     * Whether the claim's transaction rolled back and is gone from its manager;
     * absence alone proves nothing, as a commit removes it before callbacks.
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
