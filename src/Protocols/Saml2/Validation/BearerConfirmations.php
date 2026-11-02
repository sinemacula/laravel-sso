<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Validation;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlAssertion;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SamlResponse;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\SubjectConfirmation;

/**
 * Chooses the bearer `SubjectConfirmation` a SAML assertion is accepted by
 * (SSO-6.4 to SSO-6.6, SAML 2.0 Profiles §4.1.4.2), and binds the response to
 * the consumed request.
 *
 * First, the response's own `InResponseTo` must be the consumed request's SAML
 * request id, compared exactly, or absent for the unsolicited profile, and no
 * bearer confirmation may name another request (one naming none is judged by
 * the rules below), or the response is `request_mismatch`: correlation is
 * authenticated by the signed `InResponseTo` of a bearer confirmation, and
 * every other one must agree. The envelope's agreement covers a plain assertion
 * before anything is consumed; this covers an encrypted one, whose
 * confirmations the envelope cannot see.
 *
 * Then one bearer confirmation must satisfy every rule on its own, never by
 * combining several, each in this order:
 *
 * 1. it carries `SubjectConfirmationData` whose `Recipient` is the connection's
 *    assertion consumer service URL, compared exactly (`recipient_mismatch`);
 * 2. it carries `NotOnOrAfter`, and now is before it plus the skew
 *    (`assertion_expired`);
 * 3. it carries no `NotBefore` (`assertion_expired`);
 * 4. its `InResponseTo` is the consumed request's SAML request id, or absent
 *    for the unsolicited profile (`request_mismatch`).
 *
 * Of the confirmations that satisfy every rule, the one with the latest
 * `NotOnOrAfter`, compared to the microsecond, is chosen, the first in document
 * order on a tie, so the replay record's expiry covers every confirmation that
 * could be chosen later, even one ending a fraction of a second after. When
 * none does, the refusal is the reason of the rule the confirmation that got
 * furthest broke, the first in document order on a tie; with no bearer
 * confirmation at all it is `recipient_mismatch`. Nothing here keeps anything.
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
     * The bearer confirmation the assertion is accepted by, or why none is.
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
     * Whether the response's own `InResponseTo` is the consumed request's SAML
     * request id, or absent for the unsolicited profile.
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
     * Whether no bearer confirmation names a request other than the consumed
     * one, compared exactly; one naming none passes.
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
     * The best candidate and how many rules it satisfied: the furthest, and of
     * those satisfying every rule the latest to expire, the first on a tie;
     * none, having satisfied none, when there is no candidate.
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
     * How the candidate ranks: how many rules it satisfied in order, then, for
     * one satisfying every rule, when its `NotOnOrAfter` falls, to the
     * microsecond, so two a fraction of a second apart never tie.
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
     * How many of the rules the candidate satisfies before it breaks one.
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
     * The reason a candidate that satisfied that many rules refuses with: the
     * reason of the rule it broke.
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
