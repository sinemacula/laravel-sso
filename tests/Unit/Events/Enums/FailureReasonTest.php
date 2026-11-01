<?php

declare(strict_types = 1);

namespace Tests\Unit\Events\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Unit tests for the failure reasons: every code SSO-10.2 names is one, each
 * value is a snake_case code, and the values are stable.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FailureReason::class)]
final class FailureReasonTest extends TestCase
{
    /**
     * Every code SSO-10.2 names is a reason.
     *
     * @return void
     */
    public function testEveryCodeOfTheRequirementIsAReason(): void
    {
        $codes = [
            'connection_unavailable', 'request_unknown', 'request_expired', 'signature_invalid', 'issuer_mismatch',
            'audience_mismatch', 'recipient_mismatch', 'assertion_expired', 'replayed', 'nonce_mismatch', 'provider_error',
            'metadata_expired', 'application_not_allowed', 'unlinked', 'purpose_mismatch', 'verifier_mismatch',
        ];

        foreach ($codes as $code) {
            self::assertInstanceOf(FailureReason::class, FailureReason::tryFrom($code), "SSO-10.2 code {$code} is not a reason.");
        }
    }

    /**
     * The reasons are these, in this order: a code is never renamed or reused,
     * so a change here is a deliberate one.
     *
     * @return void
     */
    public function testTheReasonsAreStable(): void
    {
        self::assertSame([
            'connection_unavailable', 'application_not_allowed', 'request_unknown', 'request_expired', 'signature_invalid',
            'issuer_mismatch', 'audience_mismatch', 'recipient_mismatch', 'assertion_expired', 'replayed', 'nonce_mismatch',
            'provider_error', 'metadata_expired', 'unlinked', 'purpose_mismatch', 'verifier_mismatch', 'rate_limited',
            'challenge_invalid', 'session_ineligible', 'discovery_no_match', 'connection_mismatch', 'application_mismatch',
            'enforcement_unsatisfied', 'handoff_unknown', 'handoff_expired', 'link_changed',
            'fetch_refused', 'fetch_failed', 'freshness_required', 'connection_not_found', 'key_not_found',
            'settings_invalid', 'protocol_unavailable', 'key_state_conflict', 'domain_not_found', 'domain_unavailable',
            'domain_claim_expired', 'domain_record_not_found', 'domain_lookup_failed', 'feature_disabled',
            'completed_sign_in_required', 'link_not_found', 'link_limit_reached', 'subject_already_linked', 'connection_has_links',
        ], array_column(FailureReason::cases(), 'value'));
    }

    /**
     * Each value is a lower-case snake_case code, and each case's name is its
     * value in upper case.
     *
     * @return void
     */
    public function testEachValueIsASnakeCaseCode(): void
    {
        foreach (FailureReason::cases() as $reason) {
            self::assertMatchesRegularExpression('/^[a-z]+(?:_[a-z]+)*$/', $reason->value);
            self::assertSame(strtoupper($reason->value), $reason->name);
        }
    }
}
