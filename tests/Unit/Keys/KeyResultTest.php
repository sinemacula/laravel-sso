<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyStatus;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;

/**
 * Unit tests for what a key operation returns: one named constructor per
 * outcome, each setting only its own payload, the refusals a key operation may
 * give and no other, an invalid result that names at least one violation, the
 * predicates, the stable statuses, and the JSON form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyResult::class)]
#[CoversClass(KeyStatus::class)]
final class KeyResultTest extends TestCase
{
    /**
     * The statuses are these, in this order: a status is never renamed or
     * reused.
     *
     * @return void
     */
    public function testTheStatusesAreStable(): void
    {
        self::assertSame(
            ['added', 'made_current', 'retired', 'trusted', 'distrusted', 'refused', 'invalid'],
            array_column(KeyStatus::cases(), 'value'),
        );
    }

    /**
     * Rows of `[result, status]`: each success, built through its named
     * constructor.
     *
     * @return iterable<string, array{
     *     0: \Closure(\SineMacula\Laravel\Sso\Keys\KeySummary): \SineMacula\Laravel\Sso\Keys\KeyResult,
     *     1: \SineMacula\Laravel\Sso\Keys\Enums\KeyStatus
     * }>
     */
    public static function provideSuccesses(): iterable
    {
        yield from [
            'added'      => [static fn (KeySummary $key): KeyResult => KeyResult::added($key), KeyStatus::ADDED],
            'retired'    => [static fn (KeySummary $key): KeyResult => KeyResult::retired($key), KeyStatus::RETIRED],
            'trusted'    => [static fn (KeySummary $key): KeyResult => KeyResult::trusted($key), KeyStatus::TRUSTED],
            'distrusted' => [static fn (KeySummary $key): KeyResult => KeyResult::distrusted($key), KeyStatus::DISTRUSTED],
        ];
    }

    /**
     * Each success carries the key it acted on, and no previous key, reason or
     * violation.
     *
     * @param  \Closure(\SineMacula\Laravel\Sso\Keys\KeySummary): \SineMacula\Laravel\Sso\Keys\KeyResult  $make
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyStatus  $status
     * @return void
     */
    #[DataProvider('provideSuccesses')]
    public function testEachSuccessCarriesItsKey(\Closure $make, KeyStatus $status): void
    {
        $key    = self::summary('01jbkey0000000000000000001');
        $result = $make($key);

        self::assertSame($status, $result->status);
        self::assertSame($key, $result->key);
        self::assertNull($result->previous);
        self::assertNull($result->reason);
        self::assertSame([], $result->violations);
        self::assertTrue($result->isSucceeded());
        self::assertFalse($result->isRefused());
        self::assertFalse($result->isInvalid());
    }

    /**
     * A key made current carries the key it replaced, when there was one.
     *
     * @return void
     */
    public function testAKeyMadeCurrentCarriesTheKeyItReplaced(): void
    {
        $key      = self::summary('01jbkey0000000000000000002', KeyState::CURRENT);
        $previous = self::summary('01jbkey0000000000000000001', KeyState::RETIRING);

        $result = KeyResult::madeCurrent($key, $previous);

        self::assertSame(KeyStatus::MADE_CURRENT, $result->status);
        self::assertSame($key, $result->key);
        self::assertSame($previous, $result->previous);
        self::assertNull($result->reason);
        self::assertTrue($result->isSucceeded());

        self::assertNull(KeyResult::madeCurrent($key, null)->previous);
    }

    /**
     * Rows of `[reason]`: each reason a key operation is refused for.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Events\Enums\FailureReason}>
     */
    public static function provideRefusals(): iterable
    {
        yield from [
            'freshness required'   => [FailureReason::FRESHNESS_REQUIRED],
            'connection not found' => [FailureReason::CONNECTION_NOT_FOUND],
            'key not found'        => [FailureReason::KEY_NOT_FOUND],
            'key state conflict'   => [FailureReason::KEY_STATE_CONFLICT],
        ];
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
        $result = KeyResult::refused($reason);

        self::assertSame(KeyStatus::REFUSED, $result->status);
        self::assertSame($reason, $result->reason);
        self::assertNull($result->key);
        self::assertNull($result->previous);
        self::assertSame([], $result->violations);
        self::assertTrue($result->isRefused());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isInvalid());
    }

    /**
     * Every other reason is not one a key operation is refused for.
     *
     * @return void
     */
    public function testRefusesEveryOtherReason(): void
    {
        $allowed = [FailureReason::FRESHNESS_REQUIRED, FailureReason::CONNECTION_NOT_FOUND, FailureReason::KEY_NOT_FOUND, FailureReason::KEY_STATE_CONFLICT];

        foreach (FailureReason::cases() as $reason) {

            if (in_array($reason, $allowed, true)) {
                continue;
            }

            try {
                KeyResult::refused($reason);

                self::fail(sprintf('A key operation was refused for [%s].', $reason->value));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('A key operation is not refused for [%s].', $reason->value), $exception->getMessage());
            }
        }
    }

    /**
     * An invalid result carries its violations, as `settings_invalid`.
     *
     * @return void
     */
    public function testAnInvalidResultCarriesItsViolations(): void
    {
        $violations = [new SettingViolation('use', ViolationCode::NOT_ALLOWED), new SettingViolation('key_type', ViolationCode::NOT_ALLOWED)];

        $result = KeyResult::invalid($violations);

        self::assertSame(KeyStatus::INVALID, $result->status);
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertSame($violations, $result->violations);
        self::assertNull($result->key);
        self::assertNull($result->previous);
        self::assertTrue($result->isInvalid());
        self::assertFalse($result->isSucceeded());
        self::assertFalse($result->isRefused());
    }

    /**
     * An invalid result names at least one violation.
     *
     * @return void
     */
    public function testAnInvalidResultNeedsAViolation(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('An invalid result names at least one violation.');

        KeyResult::invalid([]);
    }

    /**
     * The JSON form names the status, the key and previous key as their
     * summaries, the reason and the violations.
     *
     * @return void
     */
    public function testSerializesToJson(): void
    {
        $key      = self::summary('01jbkey0000000000000000002', KeyState::CURRENT);
        $previous = self::summary('01jbkey0000000000000000001', KeyState::RETIRING);

        self::assertSame([
            'status'     => 'made_current',
            'key'        => $key->jsonSerialize(),
            'previous'   => $previous->jsonSerialize(),
            'reason'     => null,
            'violations' => [],
        ], KeyResult::madeCurrent($key, $previous)->jsonSerialize());

        self::assertSame([
            'status'     => 'refused',
            'key'        => null,
            'previous'   => null,
            'reason'     => 'key_state_conflict',
            'violations' => [],
        ], KeyResult::refused(FailureReason::KEY_STATE_CONFLICT)->jsonSerialize());

        self::assertSame(
            '{"status":"invalid","key":null,"previous":null,"reason":"settings_invalid","violations":[{"setting":"certificate","code":"duplicate"}]}',
            json_encode(KeyResult::invalid([new SettingViolation('certificate', ViolationCode::DUPLICATE)])),
        );

        self::assertSame(
            [['setting' => 'certificate', 'code' => 'duplicate']],
            KeyResult::invalid([new SettingViolation('certificate', ViolationCode::DUPLICATE)])->jsonSerialize()['violations'],
        );

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });

        try {
            $reason = KeyResult::madeCurrent($key, null)->jsonSerialize()['reason'];
        } finally {
            restore_error_handler();
        }

        self::assertNull($reason);
    }

    /**
     * A summary of a key, with no public half.
     *
     * @param  string  $id
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function summary(string $id, ?KeyState $state = KeyState::NEXT): KeySummary
    {
        return new KeySummary(
            id: $id,
            connectionId: '01jbconnection000000000001',
            use: KeyUse::SP_SIGNING,
            state: $state,
            type: KeyType::EC,
            bits: 256,
            key: MaskedKey::unset(),
            notBefore: null,
            notAfter: null,
            madeCurrentAt: null,
            retiringUntil: null,
            createdAt: CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        );
    }
}
