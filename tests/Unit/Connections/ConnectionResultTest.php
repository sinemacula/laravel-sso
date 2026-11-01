<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\ConnectionSummary;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Secrets\MaskedSecret;

/**
 * Unit tests for the result of a change to a connection: one constructor per
 * outcome, each carrying only its own payload, the predicates, the reasons a
 * change may be refused for, and its JSON.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionResult::class)]
#[CoversClass(ConnectionStatus::class)]
final class ConnectionResultTest extends TestCase
{
    /**
     * Each success carries the summary, and only `updated` what changed.
     *
     * @return void
     */
    public function testEachSuccessCarriesTheSummary(): void
    {
        $summary = self::summary();

        $created   = ConnectionResult::created($summary);
        $updated   = ConnectionResult::updated($summary, ['issuer', 'display_name']);
        $unchanged = ConnectionResult::unchanged($summary);
        $enabled   = ConnectionResult::enabled($summary);

        self::assertSame(ConnectionStatus::CREATED, $created->status);
        self::assertSame(ConnectionStatus::UPDATED, $updated->status);
        self::assertSame(ConnectionStatus::UNCHANGED, $unchanged->status);
        self::assertSame(ConnectionStatus::ENABLED, $enabled->status);

        foreach ([$created, $updated, $unchanged, $enabled] as $result) {
            self::assertSame($summary, $result->connection);
            self::assertNull($result->reason);
            self::assertSame([], $result->violations);
            self::assertTrue($result->isSucceeded());
            self::assertFalse($result->isRefused());
            self::assertFalse($result->isInvalid());
        }

        self::assertSame(['issuer', 'display_name'], $updated->changedSettings);
        self::assertSame([], $created->changedSettings);
        self::assertSame([], $unchanged->changedSettings);
        self::assertSame([], $enabled->changedSettings);

        self::assertTrue($created->isChanged());
        self::assertTrue($updated->isChanged());
        self::assertTrue($enabled->isChanged());
        self::assertFalse($unchanged->isChanged());
    }

    /**
     * An update names what changed; a change of nothing is `unchanged`.
     *
     * @return void
     */
    public function testAnUpdateNamesWhatChanged(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An updated connection names what changed; a change of nothing is unchanged.');

        ConnectionResult::updated(self::summary(), []);
    }

    /**
     * Rows of `[reason]`: each reason a change to a connection is refused for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        foreach ([FailureReason::FRESHNESS_REQUIRED, FailureReason::CONNECTION_NOT_FOUND, FailureReason::PROTOCOL_UNAVAILABLE] as $reason) {
            yield $reason->value => [$reason];
        }
    }

    /**
     * A refusal carries its reason and nothing else.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideRefusals')]
    public function testARefusalCarriesItsReason(FailureReason $reason): void
    {
        $result = ConnectionResult::refused($reason);

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame($reason, $result->reason);
        self::assertNull($result->connection);
        self::assertSame([], $result->changedSettings);
        self::assertSame([], $result->violations);
        self::assertTrue($result->isRefused());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isChanged());
        self::assertFalse($result->isInvalid());
    }

    /**
     * Rows of `[reason]`: every reason a change to a connection is never
     * refused for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideOtherReasons(): iterable
    {
        $refusals = [FailureReason::FRESHNESS_REQUIRED, FailureReason::CONNECTION_NOT_FOUND, FailureReason::PROTOCOL_UNAVAILABLE];

        foreach (FailureReason::cases() as $reason) {

            if (in_array($reason, $refusals, true)) {
                continue;
            }

            yield $reason->value => [$reason];
        }
    }

    /**
     * Any other reason is the caller's mistake, `settings_invalid` included,
     * which only `invalid()` carries.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @return void
     */
    #[DataProvider('provideOtherReasons')]
    public function testRefusesAnyOtherReason(FailureReason $reason): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage(sprintf('A change to a connection is not refused for [%s].', $reason->value));

        ConnectionResult::refused($reason);
    }

    /**
     * An invalid change carries every violation and `settings_invalid`.
     *
     * @return void
     */
    public function testAnInvalidChangeCarriesItsViolations(): void
    {
        $violations = [new SettingViolation('issuer', ViolationCode::NOT_HTTPS), new SettingViolation('display_name', ViolationCode::REQUIRED)];
        $result     = ConnectionResult::invalid($violations);

        self::assertSame(ConnectionStatus::INVALID, $result->status);
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, $result->violations);
        self::assertNull($result->connection);
        self::assertSame([], $result->changedSettings);
        self::assertTrue($result->isInvalid());
        self::assertFalse($result->isRefused());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isChanged());
    }

    /**
     * An invalid change names at least one violation.
     *
     * @return void
     */
    public function testAnInvalidChangeNamesAViolation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An invalid change names at least one violation.');

        ConnectionResult::invalid([]);
    }

    /**
     * The statuses are the six outcomes.
     *
     * @return void
     */
    public function testNamesEveryOutcome(): void
    {
        self::assertSame(
            ['created', 'updated', 'unchanged', 'enabled', 'refused', 'invalid'],
            array_map(static fn (ConnectionStatus $status): string => $status->value, ConnectionStatus::cases()),
        );
    }

    /**
     * The JSON holds the status, the connection, what changed, the reason and
     * the violations, under snake_case keys.
     *
     * @return void
     */
    public function testSerializesEachOutcome(): void
    {
        $summary = self::summary();

        self::assertSame([
            'status'           => 'updated',
            'connection'       => $summary->jsonSerialize(),
            'changed_settings' => ['client_secret'],
            'reason'           => null,
            'violations'       => [],
        ], ConnectionResult::updated($summary, ['client_secret'])->jsonSerialize());

        self::assertSame(
            '{"status":"invalid","connection":null,"changed_settings":[],"reason":"settings_invalid","violations":[{"setting":"scopes","code":"openid_scope_required"}]}',
            json_encode(ConnectionResult::invalid([new SettingViolation('scopes', ViolationCode::OPENID_SCOPE_REQUIRED)])),
        );

        self::assertSame(
            '{"status":"refused","connection":null,"changed_settings":[],"reason":"freshness_required","violations":[]}',
            json_encode(ConnectionResult::refused(FailureReason::FRESHNESS_REQUIRED)),
        );

        self::assertStringContainsString('"client_secret":{"set":true}', (string) json_encode(ConnectionResult::created($summary)));

        self::assertSame(
            [['setting' => 'scopes', 'code' => 'openid_scope_required']],
            ConnectionResult::invalid([new SettingViolation('scopes', ViolationCode::OPENID_SCOPE_REQUIRED)])->jsonSerialize()['violations'],
        );

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });

        try {
            $reason = ConnectionResult::created($summary)->jsonSerialize()['reason'];
        } finally {
            restore_error_handler();
        }

        self::assertNull($reason);
    }

    /**
     * A summary of an OIDC connection with its client secret set.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSummary
     */
    private static function summary(): ConnectionSummary
    {
        $now = CarbonImmutable::parse('2026-11-01T09:30:00Z');

        return new ConnectionSummary(
            id: '01jbexampleconnection00000',
            tenantId: 'tenant-1',
            protocol: 'oidc',
            displayName: 'Example',
            settings: ['issuer' => 'https://idp.example.com'],
            secrets: ['client_secret' => MaskedSecret::set()],
            attributeMapping: ['email' => 'email'],
            enabled: false,
            hasCompletedSignIn: false,
            usable: false,
            createdAt: $now,
            updatedAt: $now,
        );
    }
}
