<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;

/**
 * Chooses the bearer confirmation a SAML assertion is accepted by, binding the
 * response to the consumed request. One confirmation must pass every rule on
 * its own.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class BearerConfirmations
{
    /** @var int How many rules a confirmation must satisfy. */
    private const int RULES = 4;

    /**
     * Disallow instantiation; utility container only.
     */
    private function __construct() {}

    /**
     * The bearer confirmation the assertion is accepted by, or why none is. The
     * check covers an encrypted assertion the envelope could not see into.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason|\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation
     */
    public static function chosen(SamlResponse $response, SamlAssertion $assertion, ValidationContext $context): FailureReason|SubjectConfirmation
    {
        $bearers = self::bearers($assertion);

        if (!self::isAnswer($response, $context) || !self::isUnanimous($bearers, $context)) {
            return FailureReason::REQUEST_MISMATCH;
        }

        [$best, $progress] = self::best($bearers, $context);

        return $best !== null && $progress === self::RULES ? $best : self::reason($progress);
    }

    /**
     * Whether the response's `InResponseTo` is the expected one, or absent for
     * the unsolicited profile.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse  $response
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    public static function isAnswer(SamlResponse $response, ValidationContext $context): bool
    {
        return $response->inResponseTo() === $context->expectedRequestId();
    }

    /**
     * Whether no bearer confirmation names another request; naming none passes.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>  $bearers
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return bool
     */
    private static function isUnanimous(array $bearers, ValidationContext $context): bool
    {
        $expected = $context->expectedRequestId();

        foreach ($bearers as $bearer) {

            $named = $bearer->inResponseTo();

            if ($named !== null && $named !== $expected) {
                return false;
            }
        }

        return true;
    }

    /**
     * The assertion's bearer confirmations, in document order.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion  $assertion
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>
     */
    private static function bearers(SamlAssertion $assertion): array
    {
        $confirmations = $assertion->subject()?->confirmations() ?? [];

        return array_values(array_filter($confirmations, static fn (SubjectConfirmation $confirmation): bool => $confirmation->isBearer()));
    }

    /**
     * The best candidate and its progress: the furthest, then the latest to
     * expire, the first on a tie; `[null, 0]` with no candidate.
     *
     * @param  list<\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation>  $candidates
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return array{0: ?\SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation, 1: int}
     */
    private static function best(array $candidates, ValidationContext $context): array
    {
        $best = $candidates[0] ?? null;

        if ($best === null) {
            return [null, 0];
        }

        $bestRank = self::rank($best, $context);

        foreach (array_slice($candidates, 1) as $candidate) {

            $rank = self::rank($candidate, $context);

            if (($rank <=> $bestRank) <= 0) {
                continue;
            }

            $best     = $candidate;
            $bestRank = $rank;
        }

        return [$best, $bestRank[0]];
    }

    /**
     * The candidate's progress, then its expiry to the microsecond, so the
     * replay record covers any confirmation that could be chosen later.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $candidate
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return array{0: int, 1: int}
     */
    private static function rank(SubjectConfirmation $candidate, ValidationContext $context): array
    {
        $progress = self::progress($candidate, $context);
        $expiry   = $progress === self::RULES ? self::microseconds($candidate->notOnOrAfter()) : 0;

        return [$progress, $expiry];
    }

    /**
     * The instant as microseconds since the Unix epoch, or 0 for none.
     *
     * @param  ?\Carbon\CarbonImmutable  $instant
     * @return int
     */
    private static function microseconds(?CarbonImmutable $instant): int
    {
        return $instant === null ? 0 : $instant->getTimestamp() * 1000000 + $instant->micro;
    }

    /**
     * How many rules the candidate passes before breaking one: `Recipient`,
     * `NotOnOrAfter`, no `NotBefore`, `InResponseTo`.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation  $candidate
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Validation\ValidationContext  $context
     * @return int
     */
    private static function progress(SubjectConfirmation $candidate, ValidationContext $context): int
    {
        $notOnOrAfter = $candidate->notOnOrAfter();

        $rules = [
            $candidate->hasData()  && $candidate->recipient() === $context->assertionConsumerService,
            $notOnOrAfter !== null && $context->isBefore($notOnOrAfter),
            $candidate->notBefore()    === null,
            $candidate->inResponseTo() === $context->expectedRequestId(),
        ];

        $broken = array_search(false, $rules, true);

        return $broken === false ? self::RULES : $broken;
    }

    /**
     * The reason for the rule a candidate with this progress broke.
     *
     * @param  int  $progress
     * @return \SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    private static function reason(int $progress): FailureReason
    {
        return match ($progress) {
            0       => FailureReason::RECIPIENT_MISMATCH,
            1, 2    => FailureReason::ASSERTION_EXPIRED,
            default => FailureReason::REQUEST_MISMATCH,
        };
    }
}
