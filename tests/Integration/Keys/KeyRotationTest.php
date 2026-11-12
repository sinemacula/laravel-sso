<?php

declare(strict_types = 1);

namespace Tests\Integration\Keys;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyResult;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeyService;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Integration test of an encryption key's whole rotation through the helpers
 * and the key ring.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyService::class)]
#[CoversClass(KeyRing::class)]
final class KeyRotationTest extends TestCase
{
    use UsesConnections;

    /** @var string The tenant whose connection rotates its keys. */
    private const string TENANT = 'tenant-1';

    /** @var int The overlap configured, in seconds: an hour. */
    private const int OVERLAP = 3600;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The tenant's SAML connection. */
    private Connection $connection;

    /**
     * Bind a fixed clock and fresh freshness, set the overlap, and create a
     * SAML connection.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);
        $this->app?->instance(Freshness::class, new RecordingFreshness);

        config()->set('sso.keys.overlap_seconds', self::OVERLAP);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);
    }

    /**
     * An encryption key rotates without downtime through add, publish, promote,
     * overlap and retire.
     *
     * @return void
     */
    public function testRotatesAnEncryptionKeyThroughItsWholeLifecycle(): void
    {
        $id = $this->connection->id;

        // The first key is current at once, and alone decrypts
        $old = self::summaryOf($this->keys()->addNext(self::TENANT, $id, KeyUse::SP_ENCRYPTION, Clients::browser()));

        self::assertSame(KeyState::CURRENT, $old->state);
        self::assertSame([$old->id], self::ids($this->ring()->published($id, KeyUse::SP_ENCRYPTION)));
        self::assertSame([$old->id], self::ids($this->ring()->decryption($id)));
        self::assertSame([[$old->id, 'current', '2026-11-01 09:30:00', null]], $this->rows());

        // A next key is published alongside it, and does not yet decrypt
        $this->clock->advance(86400);

        $new = self::summaryOf($this->keys()->addNext(self::TENANT, $id, KeyUse::SP_ENCRYPTION, Clients::browser()));

        self::assertSame(KeyState::NEXT, $new->state);
        self::assertSame([$old->id, $new->id], self::ids($this->ring()->published($id, KeyUse::SP_ENCRYPTION)));
        self::assertSame($new->id, $this->ring()->next($id, KeyUse::SP_ENCRYPTION)?->id);
        self::assertSame([$old->id], self::ids($this->ring()->decryption($id)));

        // Made current, it replaces the old key, which still decrypts
        $this->clock->advance(86400);

        $result = $this->keys()->makeCurrent(self::TENANT, $id, $new->id, Clients::browser());

        self::assertSame($old->id, $result->previous?->id);
        self::assertSame([$new->id], self::ids($this->ring()->published($id, KeyUse::SP_ENCRYPTION)));
        self::assertSame($new->id, $this->ring()->current($id, KeyUse::SP_ENCRYPTION)?->id);
        self::assertSame([$new->id, $old->id], self::ids($this->ring()->decryption($id)));
        self::assertEqualsCanonicalizing([
            [$old->id, 'retiring', '2026-11-01 09:30:00', '2026-11-03 10:30:00'],
            [$new->id, 'current', '2026-11-03 09:30:00', null],
        ], $this->rows());

        // Until the overlap ends, then the current key alone
        $this->clock->advance(self::OVERLAP - 1);

        self::assertSame([$new->id, $old->id], self::ids($this->ring()->decryption($id)));

        $this->clock->advance(1);

        self::assertSame([$new->id], self::ids($this->ring()->decryption($id)));

        // The old key is retired; the new one decrypts with its private key
        $retired = $this->keys()->retire(self::TENANT, $id, $old->id, Clients::browser());

        self::assertTrue($retired->isSucceeded());
        self::assertSame([[$new->id, 'current', '2026-11-03 09:30:00', null]], $this->rows());
        self::assertSame($new->key->publicKey, self::publicKeyOf($this->ring()->privateKey($id, $new->id)->reveal()));

        $stored = ConnectionKey::query()->findOrFail($new->id)->getRawOriginal('private_key');

        self::assertIsString($stored);
        self::assertStringNotContainsString('PRIVATE KEY', $stored);

        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);

        self::assertSame($new->key->publicKey, self::publicKeyOf($encrypter->decrypt($stored)));
    }

    /**
     * The connection's rows as stored: id, state, current-since and
     * retiring-until.
     *
     * @return list<array{0: mixed, 1: mixed, 2: mixed, 3: mixed}>
     */
    private function rows(): array
    {
        return array_values(ConnectionKey::query()->where('connection_id', $this->connection->id)->orderBy('created_at')->get()->map(static fn (ConnectionKey $key): array => [
            $key->getRawOriginal('id'),
            $key->getRawOriginal('state'),
            $key->getRawOriginal('made_current_at'),
            $key->getRawOriginal('retiring_until'),
        ])->all());
    }

    /**
     * The key helpers, as the container builds them.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyService
     */
    private function keys(): KeyService
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyService::class);
    }

    /**
     * The key ring, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Keys\KeyRing
     */
    private function ring(): KeyRing
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app = $this->app;

        return $app->make(KeyRing::class);
    }

    /**
     * The public key of the private key PEM.
     *
     * @param  string  $privateKey
     * @return ?string
     */
    private static function publicKeyOf(string $privateKey): ?string
    {
        $key = openssl_pkey_get_private($privateKey);

        self::assertNotFalse($key);

        $details = openssl_pkey_get_details($key);

        return $details === false ? null : $details['key'];
    }

    /**
     * The summary the result carries, which it must.
     *
     * @param  \SineMacula\Laravel\Sso\Keys\KeyResult  $result
     * @return \SineMacula\Laravel\Sso\Keys\KeySummary
     */
    private static function summaryOf(KeyResult $result): KeySummary
    {
        self::assertNotNull($result->key, sprintf('The helper answered %s (%s).', $result->status->value, $result->reason->value ?? 'no reason'));

        return $result->key;
    }

    /**
     * The ids of the summaries, in order.
     *
     * @param  list<\SineMacula\Laravel\Sso\Keys\KeySummary>  $keys
     * @return list<string>
     */
    private static function ids(array $keys): array
    {
        return array_map(static fn (KeySummary $key): string => $key->id, $keys);
    }
}
