<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Handoffs\Redemption;

use SineMacula\Laravel\Sso\Contracts\LinkEligibility;
use SineMacula\Laravel\Sso\Contracts\LinkStorage;
use SineMacula\Laravel\Sso\Contracts\PurposeBranch;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Freshness\FreshnessGate;
use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * Judges and admits a `link` redemption: no session, no evidence.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkBranch implements PurposeBranch
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkStorageBinding  $storage
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkEligibility  $eligibility
     * @param  \SineMacula\Laravel\Sso\Freshness\FreshnessGate  $freshness
     * @param  \SineMacula\Laravel\Sso\Linking\LinkConfirmationGate  $confirmation
     */
    public function __construct(

        /** Resolves the result's link now, and creates or confirms it. */
        private LinkStorageBinding $storage,

        /** Whether the identity may link through the connection. */
        private LinkEligibility $eligibility,

        /** Whether the caller authenticated recently enough. */
        private FreshnessGate $freshness,

        /** Whether the caller stands apart from the identity's domain links. */
        private LinkConfirmationGate $confirmation,
    ) {}

    /**
     * Judge the caller, then, under the package's locks, the application's
     * contracts and the link as it is now.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement
     *
     * @throws \LogicException
     * @throws \SineMacula\Laravel\Sso\Exceptions\LinkCandidatesChanged
     */
    #[\Override]
    public function judge(RedemptionContext $context): Judgement
    {
        $storage  = $this->storage->require('A [link] redemption');
        $identity = $context->binding->identity;

        $caller = $context->caller;

        if (!self::isCallerBound($caller, $identity)) {
            return Judgement::of(RecheckOutcome::IDENTITY_MISMATCH);
        }

        $held = $this->confirmation->lockedDomainLinks($identity, $context->lock);
        $now  = $storage->resolve($context->result, $context->client);

        return Judgement::of($this->applicationRefusal($context, $caller, $identity, $held) ?? self::continuity($now, $identity, $context->binding));
    }

    /**
     * Create or confirm the link, judging it again so nothing is written that
     * `judge()` did not pass.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     *
     * @throws \LogicException
     */
    #[\Override]
    public function admit(RedemptionContext $context): Admission
    {
        $storage  = $this->storage->require('A [link] redemption');
        $identity = $context->binding->identity ?? throw new \LogicException('A link flow names the identity it was started for.');
        $caller   = $context->caller            ?? throw new \LogicException('A link redemption is admitted for the caller its judgement passed.');
        $held     = $this->confirmation->lockedDomainLinks($identity, $context->lock);

        if (!$this->confirmation->allows($caller, $context->connection, $held, $context->lock->domainLinkHeld)) {
            return Admission::refused(RecheckOutcome::INDEPENDENT_AUTHENTICATION_REQUIRED);
        }

        $now     = $storage->resolve($context->result, $context->client);
        $outcome = self::continuity($now, $identity, $context->binding);

        if ($outcome !== RecheckOutcome::PASSED) {
            return Admission::refused($outcome);
        }

        return $now->linkId === null ? self::created($storage, $context, $identity) : self::confirmed($storage, $context, $identity, $now->linkId);
    }

    /**
     * Whether the caller is exactly the identity the code is bound to; holding
     * the code and its verifier does not prove that.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Sso\Identities\Caller $caller
     * @phpstan-assert-if-true \SineMacula\Laravel\Sso\Identities\IdentityReference $identity
     */
    private static function isCallerBound(?Caller $caller, ?IdentityReference $identity): bool
    {
        return $identity !== null && $caller !== null && $caller->identity->is($identity);
    }

    /**
     * Why an application contract refuses the redemption, or `null`.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  list<string>  $held
     * @return ?\SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    private function applicationRefusal(RedemptionContext $context, Caller $caller, IdentityReference $identity, array $held): ?RecheckOutcome
    {
        $connection = $context->connection;

        return match (true) {
            !$this->freshness->check(FreshnessOperation::LINK_CREATE, $caller)->isFresh()             => RecheckOutcome::FRESHNESS_REQUIRED,
            !$this->eligibility->judge($identity, $connection)->isEligible()                          => RecheckOutcome::LINK_INELIGIBLE,
            !$this->confirmation->allows($caller, $connection, $held, $context->lock->domainLinkHeld) => RecheckOutcome::INDEPENDENT_AUTHENTICATION_REQUIRED,
            default                                                                                   => null,
        };
    }

    /**
     * Judge the link as it is now against the binding.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    private static function continuity(LinkResolution $now, IdentityReference $identity, HandoffBinding $binding): RecheckOutcome
    {
        return match (true) {
            $now->isReserved()                     => RecheckOutcome::LINK_RESERVED,
            self::isHeldByAnother($now, $identity) => RecheckOutcome::SUBJECT_ALREADY_LINKED,
            $now->isScopeUnknown()                 => RecheckOutcome::PRINCIPAL_SCOPE_UNKNOWN,
            self::isReplaced($now, $binding)       => RecheckOutcome::LINK_CHANGED,
            default                                => RecheckOutcome::PASSED,
        };
    }

    /**
     * Whether another identity's link holds the subject, active or suspended.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     */
    private static function isHeldByAnother(LinkResolution $now, IdentityReference $identity): bool
    {
        return $now->holder !== null && !$now->isHeldBy($identity);
    }

    /**
     * Whether the link observed at completion is not the one now, by id; a
     * binding naming a linked identity but no link counts as replaced.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $now
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffBinding  $binding
     * @return bool
     */
    private static function isReplaced(LinkResolution $now, HandoffBinding $binding): bool
    {
        return $binding->linkId === null ? $binding->linkedIdentity !== null : $binding->linkId !== $now->linkId;
    }

    /**
     * Confirm the identity's link, clearing its domain provenance and any
     * suspension.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $storage
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  string  $linkId
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    private static function confirmed(LinkStorage $storage, RedemptionContext $context, IdentityReference $identity, string $linkId): Admission
    {
        $result = $context->result;

        $storage->confirm($context->connection, $linkId, $context->client, $result->application, $result->requestReference);

        return new Admission(RecheckOutcome::PASSED, $identity, $linkId);
    }

    /**
     * Create the link, answering the store's refusal when it makes none.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\LinkStorage  $storage
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    private static function created(LinkStorage $storage, RedemptionContext $context, IdentityReference $identity): Admission
    {
        $result    = $context->result;
        $subject   = LinkSubject::of($result);
        $reference = $result->requestReference;
        $creation  = $storage->create(
            $context->connection,
            $subject,
            $identity,
            LinkOrigin::LINK_PURPOSE,
            $context->client,
            null,
            $result->application,
            $result->purpose,
            $reference,
        );

        return match ($creation->status) {
            LinkCreationStatus::CREATED                => new Admission(RecheckOutcome::PASSED, $identity, $creation->linkId()),
            LinkCreationStatus::LINK_LIMIT_REACHED     => Admission::refused(RecheckOutcome::LINK_LIMIT_REACHED),
            LinkCreationStatus::SUBJECT_ALREADY_LINKED => Admission::refused(RecheckOutcome::SUBJECT_ALREADY_LINKED),
        };
    }
}
