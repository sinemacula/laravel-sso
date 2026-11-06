<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeyRing;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the read side of a connection's keys and certificates
 * (SSO-2.6, SSO-2.7, SSO-5.9): the current and next key of a use; the keys
 * published, current then next; the keys that decrypt, the current one and each
 * retiring one until its overlap ends by the clock, newest first; the
 * certificates trusted, oldest first whatever their dates; and a private key,
 * decrypted for its own connection only. Every read is made on the write
 * connection.
 *
 * The rows are written directly, each with a distinct P-256 certificate, since
 * the ring reads them as stored; each own key's private half is the encrypted
 * private key of the fixtures' first P-256 certificate.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeyRing::class)]
final class KeyRingTest extends TestCase
{
    use UsesConnections;

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /** @var \SineMacula\Laravel\Sso\Models\Connection The connection whose keys are read. */
    private Connection $connection;

    /** @var \SineMacula\Laravel\Sso\Models\Connection Another connection, whose keys are never read for the first. */
    private Connection $other;

    /** @var int The index of the next distinct certificate a row is given. */
    private int $certificates = 1;

    /**
     * Bind a fixed clock, and create the tables and two SAML connections.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->clock = new FixedClock('2026-11-01T09:30:00Z');

        $this->app?->instance(Clock::class, $this->clock);

        $this->usePackageTables();

        $this->connection = $this->makeConnection(['protocol' => 'saml2']);
        $this->other      = $this->makeConnection(['protocol' => 'saml2']);
    }

    /**
     * The current and next key of a use are the connection's own, of that use
     * and state, or `null`.
     *
     * @return void
     */
    public function testReadsTheCurrentAndNextKeyOfAUse(): void
    {
        $current = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $next    = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::NEXT);
        $theirs  = $this->row($this->other, KeyUse::SP_SIGNING, KeyState::CURRENT);

        $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::RETIRING);

        self::assertSame($current->id, $this->ring()->current($this->connection->id, KeyUse::SP_SIGNING)?->id);
        self::assertSame($next->id, $this->ring()->next($this->connection->id, KeyUse::SP_SIGNING)?->id);
        self::assertSame($theirs->id, $this->ring()->current($this->other->id, KeyUse::SP_SIGNING)?->id);
        self::assertNull($this->ring()->next($this->other->id, KeyUse::SP_SIGNING));
        self::assertNull($this->ring()->current($this->connection->id, KeyUse::SP_ENCRYPTION));
        self::assertNull($this->ring()->current('01jbunknownconnection00000', KeyUse::SP_SIGNING));
    }

    /**
     * The keys published are the current key, then the next one, however they
     * were added; never a retiring key or another use's.
     *
     * @return void
     */
    public function testPublishesTheCurrentKeyThenTheNext(): void
    {
        self::assertSame([], $this->ring()->published($this->connection->id, KeyUse::SP_SIGNING));

        $next = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::NEXT);

        $this->clock->advance(1);

        $current = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT);

        $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::RETIRING);
        $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT);
        $this->row($this->other, KeyUse::SP_SIGNING, KeyState::NEXT);

        self::assertSame([$current->id, $next->id], self::ids($this->ring()->published($this->connection->id, KeyUse::SP_SIGNING)));

        $next->delete();

        self::assertSame([$current->id], self::ids($this->ring()->published($this->connection->id, KeyUse::SP_SIGNING)));
    }

    /**
     * Decryption accepts the current encryption key, then each retiring one
     * whose overlap has not ended, the most recently current first; a retiring
     * key stops being accepted the instant its overlap ends.
     *
     * @return void
     */
    public function testDecryptionHonorsTheOverlapAsTheClockMoves(): void
    {
        $current = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, ['made_current_at' => self::at('09:30:00')]);
        $older   = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['made_current_at' => self::at('08:00:00'), 'retiring_until' => self::at('10:30:00')]);
        $newer   = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['made_current_at' => self::at('09:00:00'), 'retiring_until' => self::at('10:00:00')]);

        $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['made_current_at' => self::at('07:00:00'), 'retiring_until' => self::at('09:30:00')]);
        $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::NEXT);
        $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::RETIRING, ['retiring_until' => self::at('11:00:00')]);
        $this->row($this->other, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['retiring_until' => self::at('11:00:00')]);

        self::assertSame([$current->id, $newer->id, $older->id], self::ids($this->ring()->decryption($this->connection->id)));

        $this->clock->advance(1799);

        self::assertSame([$current->id, $newer->id, $older->id], self::ids($this->ring()->decryption($this->connection->id)));

        $this->clock->advance(1);

        self::assertSame([$current->id, $older->id], self::ids($this->ring()->decryption($this->connection->id)));

        $this->clock->advance(1800);

        self::assertSame([$current->id], self::ids($this->ring()->decryption($this->connection->id)));
    }

    /**
     * The current encryption key decrypts first even when a retiring one was
     * made current after it, and a retiring key with no record of when it was
     * made current decrypts last.
     *
     * @return void
     */
    public function testDecryptionPutsTheCurrentKeyFirstWhateverTheDates(): void
    {
        $undated = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['retiring_until' => self::at('10:00:00')]);
        $current = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT, ['made_current_at' => self::at('08:00:00')]);
        $later   = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['made_current_at' => self::at('09:00:00'), 'retiring_until' => self::at('10:00:00')]);

        self::assertSame([$current->id, $later->id, $undated->id], self::ids($this->ring()->decryption($this->connection->id)));
    }

    /**
     * Without a current encryption key, decryption accepts the retiring keys
     * still within their overlap, and nothing once they end.
     *
     * @return void
     */
    public function testDecryptionWithoutACurrentKey(): void
    {
        $retiring = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::RETIRING, ['retiring_until' => self::at('10:00:00')]);

        self::assertSame([$retiring->id], self::ids($this->ring()->decryption($this->connection->id)));

        $this->clock->advance(1800);

        self::assertSame([], $this->ring()->decryption($this->connection->id));
    }

    /**
     * The certificates trusted are every one of the connection's, oldest first,
     * an expired one included; never an own key or another connection's
     * certificate.
     *
     * @return void
     */
    public function testReadsEveryTrustedCertificateOldestFirst(): void
    {
        $first = $this->row($this->connection, KeyUse::IDP_SIGNING, null, ['not_after' => CarbonImmutable::parse('2020-01-01T00:00:00Z')]);

        $this->clock->advance(1);

        $second = $this->row($this->connection, KeyUse::IDP_SIGNING, null);

        $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $this->row($this->other, KeyUse::IDP_SIGNING, null);

        $trusted = $this->ring()->trustedCertificates($this->connection->id);

        self::assertSame([$first->id, $second->id], self::ids($trusted));
        self::assertTrue($trusted[0]->isExpiredAt($this->clock->now()));
        self::assertNotNull($trusted[0]->key->certificate);
    }

    /**
     * A key's private half is decrypted for its own connection, as a secret.
     *
     * @return void
     */
    public function testDecryptsAPrivateKey(): void
    {
        $key    = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $secret = $this->ring()->privateKey($this->connection->id, $key->id);

        self::assertInstanceOf(Secret::class, $secret);
        self::assertSame(Certificates::privateKey(), $secret->reveal());
    }

    /**
     * A key of another connection, a trusted certificate or an unknown id has
     * no private key the connection may use: the caller's mistake.
     *
     * @return void
     */
    public function testRefusesAPrivateKeyTheConnectionDoesNotHave(): void
    {
        $theirs      = $this->row($this->other, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $certificate = $this->row($this->connection, KeyUse::IDP_SIGNING, null);

        foreach ([$theirs->id, $certificate->id, '01jbunknownkey000000000000'] as $keyId) {
            try {
                $this->ring()->privateKey($this->connection->id, $keyId);

                self::fail('A private key the connection does not have was returned.');
            } catch (\LogicException $exception) {
                self::assertSame('The connection has no private key with that id.', $exception->getMessage());
            }
        }
    }

    /**
     * A ciphertext the encrypter cannot decrypt is a server error, and
     * propagates.
     *
     * @return void
     */
    public function testADecryptionFailurePropagates(): void
    {
        $key = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT, ['private_key' => 'not-a-ciphertext']);

        $this->expectException(\RuntimeException::class);

        $this->ring()->privateKey($this->connection->id, $key->id);
    }

    /**
     * Every read is made on the write connection (SSO-11.3), so a lagging
     * replica never answers a retired key as one that still decrypts: with the
     * read connection unusable, every read still answers.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $current     = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::CURRENT);
        $next        = $this->row($this->connection, KeyUse::SP_SIGNING, KeyState::NEXT);
        $encryption  = $this->row($this->connection, KeyUse::SP_ENCRYPTION, KeyState::CURRENT);
        $certificate = $this->row($this->connection, KeyUse::IDP_SIGNING, null);
        $id          = $this->connection->id;
        $ring        = $this->ring();

        DB::connection(StorageConnection::name())->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $answers = [
                'current'   => $ring->current($id, KeyUse::SP_SIGNING)?->id,
                'next'      => $ring->next($id, KeyUse::SP_SIGNING)?->id,
                'published' => self::ids($ring->published($id, KeyUse::SP_SIGNING)),
                'decrypts'  => self::ids($ring->decryption($id)),
                'trusted'   => self::ids($ring->trustedCertificates($id)),
                'private'   => $ring->privateKey($id, $current->id)->equals(Certificates::privateKey()),
            ];
        } finally {
            DB::connection(StorageConnection::name())->setReadPdo(null);
        }

        self::assertSame([
            'current'   => $current->id,
            'next'      => $next->id,
            'published' => [$current->id, $next->id],
            'decrypts'  => [$encryption->id],
            'trusted'   => [$certificate->id],
            'private'   => true,
        ], $answers);
    }

    /**
     * Write a row of the connection, of the use and state, with a certificate
     * of its own and, for an own key, an encrypted private key.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @param  \SineMacula\Laravel\Sso\Keys\Enums\KeyUse  $use
     * @param  ?\SineMacula\Laravel\Sso\Keys\Enums\KeyState  $state
     * @param  array<string, mixed>  $columns
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private function row(Connection $connection, KeyUse $use, ?KeyState $state, array $columns = []): ConnectionKey
    {
        /** @var \SineMacula\Laravel\Sso\Contracts\SecretEncrypter $encrypter */
        $encrypter = $this->app?->make(SecretEncrypter::class);
        $masked    = MaskedKey::fromCertificate(Certificates::distinct($this->certificates++));
        $key       = new ConnectionKey;

        $key->forceFill($columns + [
            'connection_id' => $connection->id,
            'use'           => $use,
            'state'         => $state,
            'key_type'      => KeyType::EC,
            'key_bits'      => 256,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'private_key'   => $use->isOwnKey() ? $encrypter->encrypt(Certificates::privateKey()) : null,
            'fingerprint'   => $masked->fingerprint,
            'not_before'    => CarbonImmutable::parse('2026-11-01T00:00:00Z'),
            'not_after'     => CarbonImmutable::parse('2027-11-01T00:00:00Z'),
        ])->save();

        return $key;
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
     * The instant of the time on the clock's day, in UTC.
     *
     * @param  string  $time
     * @return \Carbon\CarbonImmutable
     */
    private static function at(string $time): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T' . $time . 'Z');
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
