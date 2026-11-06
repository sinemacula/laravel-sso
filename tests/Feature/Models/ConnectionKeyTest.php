<?php

declare(strict_types = 1);

namespace Tests\Feature\Models;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the keys and certificates model (SSO-2.6, SSO-2.7): its
 * table and connection, its ULID key and clock timestamps, its casts, and its
 * hidden private key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionKey::class)]
final class ConnectionKeyTest extends TestCase
{
    /**
     * Bind a fixed clock and create the tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));

        $this->usePackageTables();
    }

    /**
     * The model takes its configured table on the storage connection.
     *
     * @return void
     */
    public function testTakesItsTableAndConnection(): void
    {
        self::assertSame('sso_keys', (new ConnectionKey)->getTable());
        self::assertNull((new ConnectionKey)->getConnectionName());

        config()->set('sso.keys.table', 'idp_keys');

        self::assertSame('idp_keys', (new ConnectionKey)->getTable());
    }

    /**
     * A row reads back with its enums, sizes and times cast, is keyed by a ULID
     * and stamped by the clock, and hides its private key.
     *
     * @return void
     */
    public function testCastsItsColumnsAndHidesThePrivateKey(): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id'   => '01jbexampleconnection00000',
            'use'             => KeyUse::SP_SIGNING,
            'state'           => KeyState::CURRENT,
            'key_type'        => KeyType::RSA,
            'key_bits'        => 3072,
            'certificate'     => 'certificate-pem',
            'public_key'      => 'public-key-pem',
            'private_key'     => 'encrypted-private-key',
            'fingerprint'     => str_repeat('a', 64),
            'not_before'      => new \DateTimeImmutable('2026-11-01T09:30:00Z'),
            'not_after'       => new \DateTimeImmutable('2028-11-01T09:30:00+02:00'),
            'made_current_at' => new \DateTimeImmutable('2026-11-01T09:30:00Z'),
        ])->save();

        $read = ConnectionKey::query()->findOrFail($key->id);

        self::assertMatchesRegularExpression('/^[0-9a-hjkmnp-tv-z]{26}$/', $read->id);
        self::assertSame(KeyUse::SP_SIGNING, $read->use);
        self::assertSame(KeyState::CURRENT, $read->state);
        self::assertSame(KeyType::RSA, $read->key_type);
        self::assertSame(3072, $read->key_bits);
        self::assertSame('2028-11-01 07:30:00', $read->getRawOriginal('not_after'));
        self::assertSame('2026-11-01 09:30:00', $read->getRawOriginal('created_at'));
        self::assertNull($read->retiring_until);
        self::assertArrayNotHasKey('private_key', $read->toArray());
        self::assertSame('encrypted-private-key', $read->private_key);
    }

    /**
     * A trusted certificate has no state and no private key.
     *
     * @return void
     */
    public function testATrustedCertificateHasNoStateOrPrivateKey(): void
    {
        $key = new ConnectionKey;

        $key->forceFill([
            'connection_id' => '01jbexampleconnection00000',
            'use'           => KeyUse::IDP_SIGNING,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => 'certificate-pem',
            'public_key'    => 'public-key-pem',
            'fingerprint'   => str_repeat('b', 64),
        ])->save();

        $read = ConnectionKey::query()->findOrFail($key->id);

        self::assertNull($read->state);
        self::assertNull($read->private_key);
        self::assertSame(KeyUse::IDP_SIGNING, $read->use);
    }
}
