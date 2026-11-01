<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;

/**
 * Unit tests for the validation codes: stable, snake_case values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ViolationCode::class)]
final class ViolationCodeTest extends TestCase
{
    /**
     * The codes are these, in this order: a code is never renamed or reused.
     *
     * @return void
     */
    public function testTheCodesAreStable(): void
    {
        self::assertSame([
            'required', 'invalid_type', 'invalid_format', 'not_https', 'too_long', 'too_many', 'not_allowed', 'reserved',
            'unknown', 'duplicate', 'immutable', 'private_key_refused', 'weak_key', 'openid_scope_required', 'unsupported',
        ], array_column(ViolationCode::cases(), 'value'));
    }

    /**
     * Each value is a lower-case snake_case code, and each case's name is its
     * value in upper case.
     *
     * @return void
     */
    public function testEachValueIsASnakeCaseCode(): void
    {
        foreach (ViolationCode::cases() as $code) {
            self::assertMatchesRegularExpression('/^[a-z]+(?:_[a-z]+)*$/', $code->value);
            self::assertSame(strtoupper($code->value), $code->name);
        }
    }
}
