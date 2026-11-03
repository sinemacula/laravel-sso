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
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkConfirmationGate;
use SineMacula\Laravel\Sso\Links\Enums\LinkCreationStatus;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Links\LinkStorageBinding;
use SineMacula\Laravel\Sso\Links\LinkSubject;

/**
 * A `link` at redemption (SSO-5.11, SSO-8.5, SSO-8.8, SSO-9.9): it makes no
 * session and no further-factor proof, acknowledges no sign-in and never asks
 * the evidence contract. The caller the application has authenticated must be
 * the identity the code is bound to, compared byte for byte, since possessing
 * the code and its verifier does not prove that (`identity_mismatch`).
 *
 * The package's locks come first: under the identity's guard and the
 * connections `Handoffs\HandoffRecheck::lock()` took, the identity's verified
 * domain links and the subject's link are read by locking reads, and only then
 * is any application contract asked, so its guards come after the package's.
 * Freshness (`sso.link.create`, `freshness_required`) and
 * `Contracts\LinkEligibility` (`link_ineligible`) are asked again, and
 * same-identity idempotence bypasses neither. An identity holding a link of
 * verified domain provenance, in any connection, or that has ever held an
 * active one, then needs `Linking\LinkConfirmationGate` to pass, or the
 * redemption is `independent_authentication_required`: the provider behind that
 * link cannot confirm it, nor add a second subject that escapes its rule, and
 * removing the link first does not change that. Then, in this order, against
 * the link as it is now:
 *
 * - a live reservation is busy, `link_reserved`: never converted, and never
 *   superseded by a fresh proof;
 * - a link another identity holds, active or suspended, is
 *   `subject_already_linked`, naming nobody;
 * - a link whose scope could not be judged is `principal_scope_unknown`, for
 *   this attempt, and nothing is confirmed;
 * - a link observed at completion that is gone or replaced is `link_changed`:
 *   links are compared by id, so a link removed and made again for the same
 *   identity is refused; a binding that names a linked identity but no link
 *   cannot be compared, and fails closed the same way;
 * - a link the bound identity holds, the one observed or, with none observed,
 *   any, passes, even when it is suspended;
 * - no link, with none observed, creates one (origin `link_purpose`):
 *   `link_limit_reached` or `subject_already_linked` when the store refuses it,
 *   with nothing written.
 *
 * Admission of a link the identity already holds is its confirmation: it clears
 * the link's verified domain provenance and any suspension for good, raises the
 * connection's links version and reports `LinkConfirmed`
 * (`Links\LinkStore::confirm()`); a link with no such provenance is left as it
 * is, and reports nothing. Admission judges the link it re-reads again, so a
 * wrapper whose answer moved can never make it write what `judge()` did not
 * pass.
 *
 * The bound `Contracts\Linker` must be backed by `Contracts\LinkStorage`, since
 * a link written here must be one the resolver reads: another is a
 * `LogicException` before anything is written.
 *
 * It holds the storage binding, the eligibility, the freshness gate and the
 * confirmation gate, none of which keeps anything of one redemption for the
 * next (SSO-11.2).
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
     * Judge the caller; then, once the package's link locks are taken,
     * freshness, eligibility, the confirmation and the link as it is now. A
     * `link` captures no session provenance, so it names no link provenance.
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

        if (!self::isCallerBound($context->caller, $identity)) {
            return Judgement::of(RecheckOutcome::IDENTITY_MISMATCH);
        }

        $held = $this->confirmation->lockedDomainLinks($identity, $context->lock);
        $now  = $storage->resolve($context->result);

        return Judgement::of($this->applicationRefusal($context, $identity, $held) ?? self::continuity($now, $identity, $context->binding));
    }

    /**
     * Create the link, or confirm the one the identity holds, unless the link
     * as it is now is no longer one `judge()` passed.
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
        $held     = $this->confirmation->lockedDomainLinks($identity, $context->lock);

        if (!$this->confirmation->allows($identity, $context->connection, $held, $context->lock->domainLinkHeld)) {
            return Admission::refused(RecheckOutcome::INDEPENDENT_AUTHENTICATION_REQUIRED);
        }

        $now     = $storage->resolve($context->result);
        $outcome = self::continuity($now, $identity, $context->binding);

        if ($outcome !== RecheckOutcome::PASSED) {
            return Admission::refused($outcome);
        }

        return $now->linkId === null ? self::created($storage, $context, $identity) : self::confirmed($storage, $context, $identity, $now->linkId);
    }

    /**
     * Whether the caller the application has authenticated is the identity the
     * code is bound to, byte for byte; no caller, or no identity, is not.
     *
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $caller
     * @param  ?\SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @return bool
     *
     * @phpstan-assert-if-true \SineMacula\Laravel\Sso\Identities\IdentityReference $identity
     */
    private static function isCallerBound(?IdentityReference $caller, ?IdentityReference $identity): bool
    {
        return $identity !== null && $caller !== null && $caller->is($identity);
    }

    /**
     * Why an application contract refuses the redemption, or `null`, asked once
     * the package's locks are held: freshness, eligibility, the confirmation.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @param  \SineMacula\Laravel\Sso\Identities\IdentityReference  $identity
     * @param  list<string>  $held
     * @return ?\SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    private function applicationRefusal(RedemptionContext $context, IdentityReference $identity, array $held): ?RecheckOutcome
    {
        $connection = $context->connection;

        return match (true) {
            !$this->freshness->check(FreshnessOperation::LINK_CREATE)->isFresh()                        => RecheckOutcome::FRESHNESS_REQUIRED,
            !$this->eligibility->judge($identity, $connection)->isEligible()                            => RecheckOutcome::LINK_INELIGIBLE,
            !$this->confirmation->allows($identity, $connection, $held, $context->lock->domainLinkHeld) => RecheckOutcome::INDEPENDENT_AUTHENTICATION_REQUIRED,
            default                                                                                     => null,
        };
    }

    /**
     * What the link as it is now means for the bound identity and what was
     * observed at completion.
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
     * Whether a link holds the subject, active or suspended, and is not the
     * identity's.
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
     * Whether the link observed at completion is not the one that holds the
     * subject now. A binding naming a linked identity but no link cannot show
     * the link is the same, and counts as replaced.
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
     * Clear the identity's link of its verified domain provenance and any
     * suspension, and answer it.
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

        $storage->confirm($context->connection, $linkId, $result->application, $result->requestReference);

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
        $creation  = $storage->create($context->connection, $subject, $identity, LinkOrigin::LINK_PURPOSE, null, $result->application, $result->purpose, $reference);

        return match ($creation->status) {
            LinkCreationStatus::CREATED                => new Admission(RecheckOutcome::PASSED, $identity, $creation->linkId()),
            LinkCreationStatus::LINK_LIMIT_REACHED     => Admission::refused(RecheckOutcome::LINK_LIMIT_REACHED),
            LinkCreationStatus::SUBJECT_ALREADY_LINKED => Admission::refused(RecheckOutcome::SUBJECT_ALREADY_LINKED),
        };
    }
}
