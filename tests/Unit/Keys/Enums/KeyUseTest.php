<?php

declare(strict_types = 1);

namespace Tests\Unit\Keys\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;

/**
 * Unit tests for what a key or certificate is for: stable values, and for each
 * use whether it is the service provider's own, its protocol, the key types it
 * may hold and the freshness operation a change to it needs.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyUse::class)]
final class KeyUseTest extends TestCase
{
    /**
     * The uses are these, in this order: a value is never renamed or reused.
     *
     * @return void
     */
    public function testTheUsesAreStable(): void
    {
        self::assertSame(['sp_signing', 'sp_encryption', 'client_assertion', 'idp_signing'], array_column(KeyUse::cases(), 'value'));
    }

    /**
     * Rows of `[use, own key, protocol, allowed types, freshness]`: each use.
     *
     * @return iterable<string, array{
     *     0: \SineMacula\Laravel\Sso\Keys\Enums\KeyUse,
     *     1: bool,
     *     2: string,
     *     3: list<\SineMacula\Laravel\Sso\Keys\Enums\KeyType>,
     *     4: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation
     * }>
     */
    public static function provideUses(): iterable
    {
        yield from [
            'sp signing'       => [KeyUse::SP_SIGNING, true, 'saml2', [KeyType::RSA, KeyType::EC], FreshnessOperation::KEYS_ROTATE],
            'sp encryption'    => [KeyUse::SP_ENCRYPTION, true, 'saml2', [KeyType::RSA], FreshnessOperation::KEYS_ROTATE],
            'client assertion' => [KeyUse::CLIENT_ASSERTION, true, 'oidc', [KeyType::RSA, KeyType::EC], FreshnessOperation::KEYS_ROTATE],
            'idp signing'      => [KeyUse::IDP_SIGNING, false, 'saml2', [KeyType::RSA, KeyType::EC], FreshnessOperation::CONNECTION_TRUST],
        ];
    }

    /**
     * Each use says whether it is the service provider's own, its protocol, the
     * types it may hold and the operation a change to it needs.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  bool  $ownKey
     * @param  string  $protocol
     * @param  list<\SineMacula\Laravel\Sso\Keys\Enums\KeyType>  $types
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $freshness
     * @return void
     */
    #[DataProvider('provideUses')]
    public function testEachUseDescribesItself(KeyUse $use, bool $ownKey, string $protocol, array $types, FreshnessOperation $freshness): void
    {
        self::assertSame($ownKey, $use->isOwnKey());
        self::assertSame($protocol, $use->protocol());
        self::assertSame($types, $use->allowedTypes());
        self::assertSame($freshness, $use->freshness());
    }
}
