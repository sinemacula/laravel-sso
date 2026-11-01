<?php

declare(strict_types = 1);

namespace Tests\Feature\Keys;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Keys\Enums\KeyState;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Keys\KeySummary;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the summary of a key or certificate (SSO-2.5 to SSO-2.7):
 * read from a row's certificate, or from its bare public key when it has none;
 * its expiry answered at the edges, never enforced; and its JSON form, which
 * never holds a private key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySummary::class)]
final class KeySummaryTest extends TestCase
{
    /** @var string The id of the row summarised. */
    private const string ID = '01jbkey0000000000000000001';

    /** @var string The id of the row's connection. */
    private const string CONNECTION = '01jbconnection000000000001';

    /**
     * A row with a certificate is summarised from it: the certificate, its
     * public key and its fingerprint, with every other column as stored.
     *
     * @return void
     */
    public function testSummarizesARowFromItsCertificate(): void
    {
        $certificate = Certificates::ecP256();
        $summary     = KeySummary::of(self::row(['certificate' => $certificate]));
        $masked      = MaskedKey::fromCertificate($certificate);

        self::assertSame(self::ID, $summary->id);
        self::assertSame(self::CONNECTION, $summary->connectionId);
        self::assertSame(KeyUse::SP_SIGNING, $summary->use);
        self::assertSame(KeyState::RETIRING, $summary->state);
        self::assertSame(KeyType::EC, $summary->type);
        self::assertSame(256, $summary->bits);
        self::assertSame($masked->certificate, $summary->key->certificate);
        self::assertSame($masked->publicKey, $summary->key->publicKey);
        self::assertSame($masked->fingerprint, $summary->key->fingerprint);
        self::assertSame('2026-11-01T09:00:00+00:00', $summary->notBefore?->toIso8601String());
        self::assertSame('2027-11-01T09:00:00+00:00', $summary->notAfter?->toIso8601String());
        self::assertSame('2026-11-01T09:30:00+00:00', $summary->madeCurrentAt?->toIso8601String());
        self::assertSame('2026-11-08T09:30:00+00:00', $summary->retiringUntil?->toIso8601String());
        self::assertSame('2026-11-01T09:15:00+00:00', $summary->createdAt->toIso8601String());
    }

    /**
     * A row with no certificate is summarised from its bare public key, with no
     * certificate and no validity.
     *
     * @return void
     */
    public function testSummarizesARowFromItsBarePublicKey(): void
    {
        $publicKey = (string) MaskedKey::fromCertificate(Certificates::ecP256())->publicKey;
        $summary   = KeySummary::of(self::row(['certificate' => null, 'public_key' => $publicKey, 'not_before' => null, 'not_after' => null]));

        self::assertTrue($summary->key->isSet);
        self::assertNull($summary->key->certificate);
        self::assertSame($publicKey, $summary->key->publicKey);
        self::assertSame(MaskedKey::fromPublicKey($publicKey)->fingerprint, $summary->key->fingerprint);
        self::assertNull($summary->notAfter);
        self::assertFalse($summary->isExpiredAt(CarbonImmutable::parse('2100-01-01T00:00:00Z')));
        self::assertFalse($summary->expiresWithin(CarbonImmutable::parse('2100-01-01T00:00:00Z'), 86400));
    }

    /**
     * A certificate has expired at the instant its validity ends, and not a
     * second before.
     *
     * @return void
     */
    public function testExpiresAtTheEndOfItsValidity(): void
    {
        $summary  = KeySummary::of(self::row());
        $notAfter = CarbonImmutable::parse('2027-11-01T09:00:00Z');

        self::assertFalse($summary->isExpiredAt($notAfter->subSecond()));
        self::assertTrue($summary->isExpiredAt($notAfter));
        self::assertTrue($summary->isExpiredAt($notAfter->addYears(2)));
    }

    /**
     * A certificate expires within the seconds given when its validity ends at
     * or before their end, or has ended already.
     *
     * @return void
     */
    public function testExpiresWithinTheWarningAtItsEdges(): void
    {
        $summary  = KeySummary::of(self::row());
        $notAfter = CarbonImmutable::parse('2027-11-01T09:00:00Z');
        $warning  = 30 * 86400;

        self::assertTrue($summary->expiresWithin($notAfter->subSeconds($warning), $warning));
        self::assertFalse($summary->expiresWithin($notAfter->subSeconds($warning + 1), $warning));
        self::assertTrue($summary->expiresWithin($notAfter->addDay(), $warning));
        self::assertTrue($summary->expiresWithin($notAfter, 0));
        self::assertFalse($summary->expiresWithin($notAfter->subSecond(), 0));
    }

    /**
     * The JSON form names every field, with snake_case keys and ISO 8601 UTC
     * times, and never the private key, however the row holds it.
     *
     * @return void
     */
    public function testSerializesToJsonWithoutThePrivateKey(): void
    {
        $row     = self::row(['private_key' => 'the-encrypted-private-key']);
        $summary = KeySummary::of($row);
        $json    = (string) json_encode($summary);

        self::assertSame(
            ['id', 'connection_id', 'use', 'state', 'type', 'bits', 'key', 'not_before', 'not_after', 'made_current_at', 'retiring_until', 'created_at'],
            array_keys($summary->jsonSerialize()),
        );

        self::assertSame('retiring', $summary->jsonSerialize()['state']);
        self::assertSame('2027-11-01T09:00:00Z', $summary->jsonSerialize()['not_after']);
        self::assertSame('2026-11-08T09:30:00Z', $summary->jsonSerialize()['retiring_until']);
        self::assertStringNotContainsString('the-encrypted-private-key', $json);
        self::assertStringNotContainsString('PRIVATE KEY', $json);
        self::assertStringNotContainsString('private', $json);
    }

    /**
     * A trusted certificate's summary has no state.
     *
     * @return void
     */
    public function testATrustedCertificateHasNoState(): void
    {
        $summary = KeySummary::of(self::row(['use' => KeyUse::IDP_SIGNING, 'state' => null, 'made_current_at' => null, 'retiring_until' => null]));

        self::assertSame(KeyUse::IDP_SIGNING, $summary->use);
        self::assertNull($summary->state);
        self::assertNull($summary->jsonSerialize()['state']);
    }

    /**
     * A row, unsaved, with the columns given over a retiring EC signing key's.
     *
     * @param  array<string, mixed>  $columns
     * @return \SineMacula\Laravel\Sso\Models\ConnectionKey
     */
    private static function row(array $columns = []): ConnectionKey
    {
        $row = new ConnectionKey;

        $row->forceFill($columns + [
            'id'              => self::ID,
            'connection_id'   => self::CONNECTION,
            'use'             => KeyUse::SP_SIGNING,
            'state'           => KeyState::RETIRING,
            'key_type'        => KeyType::EC,
            'key_bits'        => 256,
            'certificate'     => Certificates::ecP256(),
            'public_key'      => (string) MaskedKey::fromCertificate(Certificates::ecP256())->publicKey,
            'private_key'     => null,
            'fingerprint'     => (string) MaskedKey::fromCertificate(Certificates::ecP256())->fingerprint,
            'not_before'      => CarbonImmutable::parse('2026-11-01T09:00:00Z'),
            'not_after'       => CarbonImmutable::parse('2027-11-01T09:00:00Z'),
            'made_current_at' => CarbonImmutable::parse('2026-11-01T09:30:00Z'),
            'retiring_until'  => CarbonImmutable::parse('2026-11-08T09:30:00Z'),
            'created_at'      => CarbonImmutable::parse('2026-11-01T09:15:00Z'),
            'updated_at'      => CarbonImmutable::parse('2026-11-01T09:30:00Z'),
        ]);

        return $row;
    }
}
