<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextKey;
use SineMacula\Laravel\Sso\Sessions\Enums\ContextValueType;

/**
 * Unit tests for the context keys and their types.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ContextKey::class)]
#[CoversClass(ContextValueType::class)]
final class ContextKeyTest extends TestCase
{
    /**
     * Every key is named exactly, in order, with its type.
     *
     * @return void
     */
    public function testEveryKeyIsNamedExactlyWithItsType(): void
    {
        $types = [];

        foreach (ContextKey::cases() as $key) {
            $types[$key->value] = $key->type()->value;
        }

        self::assertSame([
            'sso.connection'                       => 'string',
            'sso.tenant'                           => 'string',
            'sso.protocol'                         => 'string',
            'sso.provider_auth_time'               => 'time',
            'sso.provider_amr'                     => 'list',
            'sso.provider_acr'                     => 'string',
            'sso.provider_authn_context_class_ref' => 'string',
            'sso.link'                             => 'string',
            'sso.link_provenance'                  => 'string',
            'sso.provider_session_deadline'        => 'time',
            'sso.session_not_after'                => 'time',
            'sso.enforcement_version'              => 'string',
        ], $types);
        self::assertSame(['string', 'list', 'time'], array_map(static fn (ContextValueType $type): string => $type->value, ContextValueType::cases()));
    }
}
