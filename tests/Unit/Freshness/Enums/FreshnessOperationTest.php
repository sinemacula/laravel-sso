<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * Unit tests for the freshness operations: exactly the eleven stable names
 * SSO-2.12 lists, in order, each with the key its maximum age is configured
 * under, and every key in the shipped `freshness` block, which holds no other.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessOperation::class)]
final class FreshnessOperationTest extends TestCase
{
    /** @var list<string> The stable names SSO-2.12 lists, in order. */
    private const array NAMES = [
        'sso.connection.trust',
        'sso.connection.enable',
        'sso.connection.delete',
        'sso.connection.idp_initiated',
        'sso.keys.rotate',
        'sso.domain.claim',
        'sso.domain.verify',
        'sso.domain.remove',
        'sso.enforcement.update',
        'sso.link.create',
        'sso.link.remove',
    ];

    /**
     * The operations are the eleven stable names, exactly and in order.
     *
     * @return void
     */
    public function testTheOperationsAreTheStableNames(): void
    {
        self::assertSame(self::NAMES, array_column(FreshnessOperation::cases(), 'value'));
    }

    /**
     * Rows of `[operation, name, key]`: each operation, its stable name and the
     * key its maximum age is configured under.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation, 1: string, 2: string}>
     */
    public static function provideOperations(): iterable
    {
        yield from [
            'connection trust'         => [FreshnessOperation::CONNECTION_TRUST, 'sso.connection.trust', 'connection_trust'],
            'connection enable'        => [FreshnessOperation::CONNECTION_ENABLE, 'sso.connection.enable', 'connection_enable'],
            'connection delete'        => [FreshnessOperation::CONNECTION_DELETE, 'sso.connection.delete', 'connection_delete'],
            'connection idp initiated' => [FreshnessOperation::CONNECTION_IDP_INITIATED, 'sso.connection.idp_initiated', 'connection_idp_initiated'],
            'keys rotate'              => [FreshnessOperation::KEYS_ROTATE, 'sso.keys.rotate', 'keys_rotate'],
            'domain claim'             => [FreshnessOperation::DOMAIN_CLAIM, 'sso.domain.claim', 'domain_claim'],
            'domain verify'            => [FreshnessOperation::DOMAIN_VERIFY, 'sso.domain.verify', 'domain_verify'],
            'domain remove'            => [FreshnessOperation::DOMAIN_REMOVE, 'sso.domain.remove', 'domain_remove'],
            'enforcement update'       => [FreshnessOperation::ENFORCEMENT_UPDATE, 'sso.enforcement.update', 'enforcement_update'],
            'link create'              => [FreshnessOperation::LINK_CREATE, 'sso.link.create', 'link_create'],
            'link remove'              => [FreshnessOperation::LINK_REMOVE, 'sso.link.remove', 'link_remove'],
        ];
    }

    /**
     * Each operation is its stable name, and its key is that name after `sso.`
     * with the dots as underscores.
     *
     * @param  \SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation  $operation
     * @param  string  $name
     * @param  string  $key
     * @return void
     */
    #[DataProvider('provideOperations')]
    public function testEachOperationHasItsNameAndKey(FreshnessOperation $operation, string $name, string $key): void
    {
        self::assertSame($name, $operation->value);
        self::assertSame($key, $operation->configKey());
        self::assertSame($operation, FreshnessOperation::from($name));
    }

    /**
     * Every key is distinct, lower case and free of dots, so it is one key of
     * the block rather than a path into it.
     *
     * @return void
     */
    public function testEveryKeyIsDistinctAndOneSegment(): void
    {
        $keys = self::keys();

        self::assertCount(count(FreshnessOperation::cases()), array_unique($keys));

        foreach ($keys as $key) {
            self::assertMatchesRegularExpression('/\A[a-z]+(?:_[a-z]+)*\z/', $key);
        }
    }

    /**
     * The shipped `freshness` block configures every operation's key, and no
     * other.
     *
     * @return void
     */
    public function testTheShippedBlockHasEveryKeyAndNoOther(): void
    {
        /** @var array{freshness: array{max_age_seconds: array<string, int>}} $config */
        $config = require dirname(__DIR__, 4) . '/config/sso.php';

        self::assertSame(['max_age_seconds'], array_keys($config['freshness']));
        self::assertSame(self::keys(), array_keys($config['freshness']['max_age_seconds']));
    }

    /**
     * Each operation's key, in the order of the operations.
     *
     * @return list<string>
     */
    private static function keys(): array
    {
        return array_map(static fn (FreshnessOperation $operation): string => $operation->configKey(), FreshnessOperation::cases());
    }
}
