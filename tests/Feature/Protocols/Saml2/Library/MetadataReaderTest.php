<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\MetadataReader;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata;
use SineMacula\Laravel\Sso\Testing\Saml\FakeSamlResponse;
use SineMacula\Laravel\Sso\Testing\Saml\XmlSigner;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\TestCase;

/**
 * Feature tests for the metadata validation profile (SSO-2.8, SSO-6.1,
 * SSO-6.11), through the reader every import and refresh uses, on the fake
 * identity provider's metadata: the entity chosen from an aggregate by its
 * pinned id; an entity missing, named twice, wrapped or carrying a signature
 * anywhere but its own refused; with anchors, a signature of its own or of its
 * aggregate required and every signature on its path verified, one by another
 * key or tampered with refused; the earliest `validUntil` of the path as the
 * expiry, one naming no real instant, on the entity or its aggregate, refused
 * as invalid metadata; a document type, an entity or a document over the cap
 * refused; a signed aggregate of several MiB verified whole; a member other
 * than the pinned entity never validated or modelled, so one the schema or the
 * library refuses never refuses the aggregate, while the pinned entity is
 * validated with its aggregate's namespaces; only RSA certificates, once each,
 * by use; the HTTP-Redirect and HTTP-POST services, the connection's binding
 * preferred; and the read value redacted.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataReader::class)]
#[CoversClass(IdpMetadata::class)]
final class MetadataReaderTest extends TestCase
{
    /** @var string The entity id the provider has. */
    private const string ENTITY_ID = FakeSamlIdentityProvider::ENTITY_ID;

    /** @var string Another entity in an aggregate. */
    private const string OTHER = 'https://other.example.test/saml';

    /** @var string The HTTP-POST single sign-on URL the metadata names besides. */
    private const string POST_URL = 'https://idp.example.test/saml/post';

    /** @var string Where an entity's own role descriptor goes in the content given it. */
    private const string ROLE = '{role}';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The attacker, made once. */
    private static ?FakeSamlIdentityProvider $attacker = null;

    /**
     * Bind a fixed clock.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
    }

    /**
     * An entity alone is read whole: its id, its HTTP-Redirect service, its
     * signing certificate as a canonical PEM with its fingerprint, no
     * encryption certificate, its NameID format and no expiry.
     *
     * @return void
     */
    public function testReadsAnEntityWhole(): void
    {
        $metadata = $this->read(self::metadata()->toXml());

        self::assertTrue($metadata->isRead());
        self::assertNull($metadata->reason);
        self::assertNull($metadata->detail);
        self::assertSame([
            self::ENTITY_ID,
            FakeSamlIdentityProvider::SSO_URL,
            'http_redirect',
            [self::certificate(self::idp()->certificate())],
            [],
            [FakeSamlResponse::PERSISTENT],
            null,
        ], self::values($metadata));
    }

    /**
     * From an aggregate, the entity is chosen by its id alone.
     *
     * @return void
     */
    public function testChoosesTheEntityFromAnAggregateByItsId(): void
    {
        $xml = self::metadata()->with(['aggregate' => [self::OTHER, 'urn:example:third']])->toXml();

        self::assertSame(self::ENTITY_ID, $this->read($xml)->entityId());
        self::assertSame(self::OTHER, $this->read($xml, self::OTHER)->entityId());
        self::assertSame('urn:example:third', $this->read($xml, 'urn:example:third')->entityId());
    }

    /**
     * Rows of `[entity id]`: an id no entity has, one differing only in case or
     * by a trailing slash, and none.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideMissingEntities(): iterable
    {
        yield from [
            'another id'         => ['https://nobody.example.test/saml'],
            'another case'       => ['https://IDP.example.test/saml'],
            'a trailing slash'   => [self::ENTITY_ID . '/'],
            'an empty entity id' => [''],
        ];
    }

    /**
     * An entity id no entity has exactly is not found.
     *
     * @param  string  $entityId
     * @return void
     */
    #[DataProvider('provideMissingEntities')]
    public function testAnEntityNotThereIsNotFound(string $entityId): void
    {
        self::assertRefused(FailureReason::METADATA_ENTITY_NOT_FOUND, 'entity_not_found', $this->read(self::metadata()->toXml(), $entityId));
    }

    /**
     * An empty entity id never chooses an entity, even one whose entity id is
     * empty.
     *
     * @return void
     */
    public function testAnEmptyEntityIdNeverChoosesAnEntity(): void
    {
        self::assertRefused(FailureReason::METADATA_ENTITY_NOT_FOUND, 'entity_not_found', $this->read(self::metadata()->with(['entity_id' => ''])->toXml(), ''));
    }

    /**
     * An entity named twice is refused, wherever the second is: beside the
     * first with an id of its own, or with the same `ID`, which the unique
     * identifier check refuses before an entity is chosen.
     *
     * @return void
     */
    public function testAnEntityNamedTwiceIsRefused(): void
    {
        $aggregate = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $second    = self::renamedIds(self::metadata()->toXml(), 'second');
        $twice     = str_replace('</md:EntitiesDescriptor>', $second . '</md:EntitiesDescriptor>', $aggregate);

        self::assertRefused(FailureReason::METADATA_INVALID, 'duplicate_entity', $this->read($twice));
        self::assertRefused(FailureReason::METADATA_INVALID, 'duplicate_id', $this->read(self::metadata()->with(['aggregate' => [self::ENTITY_ID]])->toXml()));
    }

    /**
     * Rows of `[xml, anchored, reason, detail]`: an entity wrapped where no
     * entity may be, extensions included, and a signature where no signature
     * may be.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: bool, 2: \SineMacula\Laravel\Sso\Events\Enums\FailureReason, 3: string}>
     */
    public static function provideWrappedEntities(): iterable
    {
        $hidden = static fn (): string => self::renamedIds(self::metadata()->toXml(), 'hidden');
        $signed = static fn (): string => self::metadata()->with(['aggregate' => [self::OTHER], 'sign' => 'aggregate'])->toXml();
        $object = static fn (string $xml): string => (string) preg_replace('#</ds:KeyInfo>#', '</ds:KeyInfo><ds:Object>' . $hidden() . '</ds:Object>', $xml, 1);

        yield from [
            'a copy in the aggregate signature' => [static fn (): string => $object($signed()), true, FailureReason::METADATA_INVALID, 'duplicate_entity'],
            'the only copy in a signature'      => [
                static fn (): string => $object(str_replace('entityID="' . self::ENTITY_ID . '"', 'entityID="https://moved.example.test"', $signed())),
                false,
                FailureReason::METADATA_INVALID,
                'entity_location',
            ],
            'the only copy in extensions' => [
                static fn (): string => str_replace(
                    '<md:IDPSSODescriptor',
                    '<md:Extensions>' . $hidden() . '</md:Extensions><md:IDPSSODescriptor',
                    self::metadata()->with(['entity_id' => self::OTHER])->toXml(),
                ),
                false,
                FailureReason::METADATA_INVALID,
                'entity_location',
            ],
            'a signature in the role descriptor' => [
                static fn (): string => str_replace('<md:KeyDescriptor', self::roleSignature() . '<md:KeyDescriptor', self::metadata()->toXml()),
                false,
                FailureReason::METADATA_INVALID,
                'signature_location',
            ],
        ];
    }

    /**
     * An entity anywhere but at the root or in an aggregate, and a signature
     * anywhere in the entity but its own, are refused.
     *
     * @param  \Closure(): string  $xml
     * @param  bool  $anchored
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('provideWrappedEntities')]
    public function testAWrappedEntityOrSignatureIsRefused(\Closure $xml, bool $anchored, FailureReason $reason, string $detail): void
    {
        self::assertRefused($reason, $detail, $this->read($xml(), anchors: $anchored ? [self::idp()->certificate()] : []));
    }

    /**
     * Rows of `[changes]`: metadata signed by the provider, its entity alone,
     * in an aggregate, or the aggregate.
     *
     * @return iterable<string, array{0: array<string, mixed>}>
     */
    public static function provideSignedMetadata(): iterable
    {
        yield from [
            'the entity signed'                  => [['sign' => 'entity']],
            'an aggregate, the entity signed'    => [['aggregate' => [self::OTHER], 'sign' => 'entity']],
            'an aggregate, the aggregate signed' => [['aggregate' => [self::OTHER], 'sign' => 'aggregate']],
        ];
    }

    /**
     * With an anchor, metadata whose entity a signature by the anchor covers,
     * its own or its aggregate's, is read.
     *
     * @param  array<string, mixed>  $changes
     * @return void
     */
    #[DataProvider('provideSignedMetadata')]
    public function testMetadataSignedByAnAnchorIsRead(array $changes): void
    {
        $metadata = $this->read(self::metadata()->with($changes)->toXml(), anchors: [Certificates::distinct(0), self::idp()->certificate()]);

        self::assertTrue($metadata->isRead());
        self::assertSame(self::ENTITY_ID, $metadata->entityId());
    }

    /**
     * With an anchor, unsigned metadata is refused, alone or in an aggregate.
     *
     * @return void
     */
    public function testUnsignedMetadataIsRefusedWithAnAnchor(): void
    {
        $anchors = [self::idp()->certificate()];

        self::assertRefused(FailureReason::METADATA_SIGNATURE_INVALID, 'unsigned', $this->read(self::metadata()->toXml(), anchors: $anchors));
        self::assertRefused(FailureReason::METADATA_SIGNATURE_INVALID, 'unsigned', $this->read(self::metadata()->with(['aggregate' => [self::OTHER]])->toXml(), anchors: $anchors));
    }

    /**
     * Metadata signed by the attacker, its entity or its aggregate, is refused
     * with an anchor, and read without one: no signature is read then.
     *
     * @param  array<string, mixed>  $changes
     * @return void
     */
    #[DataProvider('provideSignedMetadata')]
    public function testMetadataSignedByTheAttackerIsRefused(array $changes): void
    {
        $xml = self::metadata()->with($changes)->signedBy(self::attacker()->signer())->toXml();

        self::assertRefused(FailureReason::METADATA_SIGNATURE_INVALID, 'signature', $this->read($xml, anchors: [self::idp()->certificate()]));
        self::assertTrue($this->read($xml)->isRead());
    }

    /**
     * Every signature on the entity's path must verify: an aggregate signed by
     * the anchor around an entity the attacker signed is refused, and the
     * reverse; both signed by the anchor is read.
     *
     * @return void
     */
    public function testEverySignatureOnThePathMustVerify(): void
    {
        $anchors  = [self::idp()->certificate()];
        $inner    = self::metadata()->with(['aggregate' => [self::OTHER], 'sign' => 'entity']);
        $attacked = self::signedRoot($inner->signedBy(self::attacker()->signer())->toXml(), self::idp()->signer());
        $reverse  = self::signedRoot($inner->toXml(), self::attacker()->signer());
        $both     = self::signedRoot($inner->toXml(), self::idp()->signer());

        self::assertRefused(FailureReason::METADATA_SIGNATURE_INVALID, 'signature', $this->read($attacked, anchors: $anchors));
        self::assertRefused(FailureReason::METADATA_SIGNATURE_INVALID, 'signature', $this->read($reverse, anchors: $anchors));
        self::assertTrue($this->read($both, anchors: $anchors)->isRead());
    }

    /**
     * A signed aggregate changed after it was signed is refused, wherever the
     * change is.
     *
     * @return void
     */
    public function testATamperedAggregateIsRefused(): void
    {
        $xml = self::metadata()->with(['aggregate' => [self::OTHER], 'sign' => 'aggregate'])->toXml();

        self::assertRefused(
            FailureReason::METADATA_SIGNATURE_INVALID,
            'signature',
            $this->read(str_replace(self::OTHER, 'https://other2.example.test/saml', $xml), anchors: [self::idp()->certificate()]),
        );
        self::assertRefused(
            FailureReason::METADATA_SIGNATURE_INVALID,
            'signature',
            $this->read(str_replace(FakeSamlIdentityProvider::SSO_URL, 'https://evil.example.test/sso', $xml), anchors: [self::idp()->certificate()]),
        );
    }

    /**
     * Rows of `[changes, expired, expiry]`: an entity and an aggregate's
     * `validUntil` around now, and when the metadata expires.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: bool, 2: ?string}>
     */
    public static function provideExpiries(): iterable
    {
        $at = static fn (string $instant): CarbonImmutable => CarbonImmutable::parse($instant);

        yield from [
            'undated'                         => [[], false, null],
            'a cache duration alone'          => [['cache_duration' => 'PT1S'], false, null],
            'the entity, a second after now'  => [['valid_until' => $at('2026-11-01T09:30:01Z')], false, '2026-11-01T09:30:01+00:00'],
            'the entity, at now'              => [['valid_until' => $at('2026-11-01T09:30:00Z')], true, null],
            'the entity, a second before now' => [['valid_until' => $at('2026-11-01T09:29:59Z')], true, null],
            'the aggregate earlier'           => [
                ['valid_until' => $at('2026-12-01T00:00:00Z'), 'aggregate' => [self::OTHER], 'aggregate_valid_until' => $at('2026-11-02T00:00:00Z')],
                false,
                '2026-11-02T00:00:00+00:00',
            ],
            'the entity earlier' => [
                ['valid_until' => $at('2026-11-02T00:00:00Z'), 'aggregate' => [self::OTHER], 'aggregate_valid_until' => $at('2026-12-01T00:00:00Z')],
                false,
                '2026-11-02T00:00:00+00:00',
            ],
            'the aggregate alone'   => [['aggregate' => [self::OTHER], 'aggregate_valid_until' => $at('2026-11-03T00:00:00Z')], false, '2026-11-03T00:00:00+00:00'],
            'the aggregate expired' => [
                ['valid_until' => $at('2026-12-01T00:00:00Z'), 'aggregate' => [self::OTHER], 'aggregate_valid_until' => $at('2026-11-01T09:30:00Z')],
                true,
                null,
            ],
        ];
    }

    /**
     * The expiry is the earliest `validUntil` of the entity and its aggregate;
     * metadata whose expiry is not after now is refused.
     *
     * @param  array<string, mixed>  $changes
     * @param  bool  $expired
     * @param  ?string  $expiry
     * @return void
     */
    #[DataProvider('provideExpiries')]
    public function testTheEarliestValidUntilIsTheExpiry(array $changes, bool $expired, ?string $expiry): void
    {
        $metadata = $this->read(self::metadata()->with($changes)->toXml());

        if ($expired) {
            self::assertRefused(FailureReason::METADATA_EXPIRED, 'expired', $metadata);

            return;
        }

        self::assertSame($expiry, $metadata->validUntil()?->toIso8601String());
    }

    /**
     * A `validUntil` the schema allows but with a year of more than four digits
     * is refused.
     *
     * @return void
     */
    public function testAValidUntilBeyondAFourDigitYearIsRefused(): void
    {
        $xml = str_replace(' entityID=', ' validUntil="10000-01-01T00:00:00Z" entityID=', self::metadata()->toXml());

        self::assertRefused(FailureReason::METADATA_INVALID, 'valid_until', $this->read($xml));
    }

    /**
     * Rows of `[valid until]`: a `validUntil` of the schema's form naming no
     * real instant, by its month, its day or its time.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnrealValidUntils(): iterable
    {
        yield from [
            'month 13'                   => ['2026-13-01T00:00:00Z'],
            'month 00'                   => ['2026-00-01T00:00:00Z'],
            'day 32'                     => ['2026-12-32T00:00:00Z'],
            '30 February'                => ['2027-02-30T00:00:00Z'],
            '29 February, a common year' => ['2027-02-29T00:00:00Z'],
            'hour 25'                    => ['2026-12-01T25:00:00Z'],
            'the end of the day and one' => ['2026-12-01T24:00:01Z'],
            'minute 60'                  => ['2026-12-01T23:60:00Z'],
            'second 60'                  => ['2026-12-01T23:59:60Z'],
            'offset +14:01'              => ['2026-12-01T00:00:00+14:01'],
        ];
    }

    /**
     * A `validUntil` naming no real instant on an enclosing aggregate, which
     * the schema never judges, is refused as invalid metadata, never thrown,
     * and the refusal names the rule alone.
     *
     * @param  string  $validUntil
     * @return void
     */
    #[DataProvider('provideUnrealValidUntils')]
    public function testAnUnrealValidUntilOnTheAggregateIsRefused(string $validUntil): void
    {
        $aggregate = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $metadata  = $this->read(str_replace('ID="_aggregate"', 'ID="_aggregate" validUntil="' . $validUntil . '"', $aggregate));

        self::assertRefused(FailureReason::METADATA_INVALID, 'valid_until', $metadata);
    }

    /**
     * A `validUntil` naming no real instant on the entity, alone or in an
     * aggregate, is refused as invalid metadata by the schema.
     *
     * @param  string  $validUntil
     * @return void
     */
    #[DataProvider('provideUnrealValidUntils')]
    public function testAnUnrealValidUntilOnTheEntityIsRefused(string $validUntil): void
    {
        $attribute = ' validUntil="' . $validUntil . '" entityID=';
        $aggregate = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $member    = ' entityID="' . self::ENTITY_ID . '"';

        self::assertRefused(FailureReason::METADATA_INVALID, 'schema', $this->read(str_replace(' entityID=', $attribute, self::metadata()->toXml())));
        self::assertRefused(FailureReason::METADATA_INVALID, 'schema', $this->read(str_replace($member, $attribute . '"' . self::ENTITY_ID . '"', $aggregate)));
    }

    /**
     * Rows of `[valid until, expiry]`: a real `validUntil` at a bound on an
     * enclosing aggregate, and the instant it is read as.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideRealValidUntils(): iterable
    {
        yield from [
            '29 February, a leap year' => ['2028-02-29T00:00:00Z', '2028-02-29T00:00:00+00:00'],
            'the end of the day'       => ['2026-12-31T24:00:00Z', '2027-01-01T00:00:00+00:00'],
            'the last second'          => ['2026-12-31T23:59:59Z', '2026-12-31T23:59:59+00:00'],
            'offset +14:00'            => ['2026-12-01T14:00:00+14:00', '2026-12-01T00:00:00+00:00'],
            'offset -14:00'            => ['2026-12-01T00:00:00-14:00', '2026-12-01T14:00:00+00:00'],
        ];
    }

    /**
     * A real `validUntil` at a bound on an enclosing aggregate is read as the
     * instant it names.
     *
     * @param  string  $validUntil
     * @param  string  $expiry
     * @return void
     */
    #[DataProvider('provideRealValidUntils')]
    public function testARealValidUntilOnTheAggregateIsRead(string $validUntil, string $expiry): void
    {
        $aggregate = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $metadata  = $this->read(str_replace('ID="_aggregate"', 'ID="_aggregate" validUntil="' . $validUntil . '"', $aggregate));

        self::assertSame($expiry, $metadata->validUntil()?->toIso8601String());
    }

    /**
     * Rows of `[valid until, expired]`: a `validUntil` with a zone, without one
     * (read as UTC), and with fractions.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideInstants(): iterable
    {
        yield from [
            'an offset, at now'           => ['2026-11-01T10:30:00+01:00', true],
            'an offset, a second later'   => ['2026-11-01T10:30:01+01:00', false],
            'no zone, a second later'     => ['2026-11-01T09:30:01', false],
            'no zone, at now'             => ['2026-11-01T09:30:00', true],
            'fractions, half a second on' => ['2026-11-01T09:30:00.500Z', false],
        ];
    }

    /**
     * A `validUntil` is read as the instant it names, one with no zone as UTC.
     *
     * @param  string  $validUntil
     * @param  bool  $expired
     * @return void
     */
    #[DataProvider('provideInstants')]
    public function testAValidUntilIsReadAsTheInstantItNames(string $validUntil, bool $expired): void
    {
        $metadata = $this->read(str_replace(' entityID=', ' validUntil="' . $validUntil . '" entityID=', self::metadata()->toXml()));

        self::assertSame(!$expired, $metadata->isRead());
        self::assertSame($expired ? FailureReason::METADATA_EXPIRED : null, $metadata->reason);
    }

    /**
     * Rows of `[xml, detail]`: a document the hardened parser refuses.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: string}>
     */
    public static function provideHostileDocuments(): iterable
    {
        $secret = dirname(__DIR__, 4) . '/Fixtures/Saml/xxe-secret.txt';

        yield from [
            'an internal entity' => [static fn (): string => '<!DOCTYPE md:EntityDescriptor [<!ENTITY x "y">]>' . self::metadata()->toXml(), 'unparseable'],
            'an external entity' => [
                static fn (): string => '<!DOCTYPE md:EntityDescriptor [<!ENTITY x SYSTEM "file://' . $secret . '">]>'
                    . str_replace('persistent<', 'persistent&x;<', self::metadata()->toXml()),
                'unparseable',
            ],
            'not XML'          => [static fn (): string => 'metadata', 'unparseable'],
            'not metadata'     => [static fn (): string => self::organization(), 'not_metadata'],
            'invalid metadata' => [static fn (): string => str_replace(' entityID=', ' validUntil="tomorrow" entityID=', self::metadata()->toXml()), 'schema'],
        ];
    }

    /**
     * A document type, an entity, a document that is not XML, a valid one that
     * is not an entity or an aggregate, and invalid metadata are refused.
     *
     * @param  \Closure(): string  $xml
     * @param  string  $detail
     * @return void
     */
    #[DataProvider('provideHostileDocuments')]
    public function testAHostileDocumentIsRefused(\Closure $xml, string $detail): void
    {
        self::assertRefused(FailureReason::METADATA_INVALID, $detail, $this->read($xml()));
    }

    /**
     * Rows of `[cap, read]`: a cap one over, at and one under the document's
     * length, and whether the document is read.
     *
     * @return iterable<string, array{0: int, 1: bool}>
     */
    public static function provideCaps(): iterable
    {
        yield from [
            'the document one under the cap' => [70001, true],
            'the document at the cap'        => [70000, true],
            'the document one over the cap'  => [69999, false],
        ];
    }

    /**
     * The document is held to the metadata cap, never the fetcher's, before it
     * is parsed: one byte over it is refused, at it or under it is read.
     *
     * @param  int  $cap
     * @param  bool  $read
     * @return void
     */
    #[DataProvider('provideCaps')]
    public function testTheDocumentIsHeldToTheMetadataCap(int $cap, bool $read): void
    {
        $xml = str_pad(self::metadata()->toXml(), 70000, "\n");

        config()->set('sso.metadata.max_bytes', $cap);
        config()->set('sso.fetcher.max_response_bytes', 1024);

        $metadata = $this->read($xml);

        self::assertSame(70000, strlen($xml));
        self::assertSame([$read, $read ? null : 'too_large'], [$metadata->isRead(), $metadata->detail]);
    }

    /**
     * An aggregate of several MiB, its whole signed by the anchor, is read once
     * the metadata cap allows it: the aggregate's signature is verified and
     * exactly the entity pinned is chosen from among more than a thousand; a
     * byte over the cap, it is refused before it is parsed.
     *
     * @return void
     */
    public function testALargeSignedAggregateIsVerifiedWholeAndItsEntityChosen(): void
    {
        $others  = array_map(static fn (int $index): string => "https://idp{$index}.example.test/saml", range(1, 1400));
        $xml     = self::metadata()->with(['aggregate' => $others, 'sign' => 'aggregate', 'aggregate_valid_until' => CarbonImmutable::parse('2026-11-08T00:00:00Z')])->toXml();
        $size    = strlen($xml);
        $anchors = [self::idp()->certificate()];

        config()->set('sso.metadata.max_bytes', $size);

        $chosen = $this->read($xml, anchors: $anchors);

        self::assertGreaterThan(2 * 1048576, $size);
        self::assertSame(
            [true, self::ENTITY_ID, FakeSamlIdentityProvider::SSO_URL, '2026-11-08T00:00:00+00:00'],
            [$chosen->isRead(), $chosen->entityId(), $chosen->ssoUrl(), $chosen->validUntil()?->toIso8601String()],
        );

        config()->set('sso.metadata.max_bytes', $size - 1);

        self::assertRefused(FailureReason::METADATA_INVALID, 'too_large', $this->read($xml, anchors: $anchors));
    }

    /**
     * Rows of `[member, pinned read]`: what a member of an aggregate may hold
     * that the library's model refuses, or the metadata schema too, and whether
     * the pinned entity holding it is still read.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideUnrelatedMembers(): iterable
    {
        yield from [
            'a relative logo'                => ['<md:Extensions>' . self::logo('/logo.png') . '</md:Extensions>' . self::ROLE, true],
            'a scheme-less organization URL' => [self::ROLE . str_replace('https://example.test', 'www.example.edu', self::organization(false)), true],
            'an unknown contact type'        => [self::ROLE . self::contact('nobody'), false],
        ];
    }

    /**
     * A signed aggregate is read for its pinned entity even when an unrelated
     * member holds what the library's model or the metadata schema refuses: the
     * aggregate's signature is verified over its bytes, no member is modelled,
     * and only the chosen entity is held to the schema, so the same value in
     * the pinned entity is refused only when the schema refuses it.
     *
     * @param  string  $member
     * @param  bool  $pinnedRead
     * @return void
     */
    #[DataProvider('provideUnrelatedMembers')]
    public function testAnUnrelatedMemberNeverRefusesTheAggregate(string $member, bool $pinnedRead): void
    {
        $anchors   = [self::idp()->certificate()];
        $aggregate = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $unrelated = self::withMember($aggregate, self::OTHER, $member);
        $pinned    = self::withMember($aggregate, self::ENTITY_ID, $member);

        self::assertSame(self::ENTITY_ID, $this->read(self::signedRoot($unrelated, self::idp()->signer()), anchors: $anchors)->entityId());
        self::assertSame(self::ENTITY_ID, $this->read($unrelated)->entityId());
        self::assertSame(
            [$pinnedRead, $pinnedRead ? null : 'schema'],
            [$this->read(self::signedRoot($pinned, self::idp()->signer()), anchors: $anchors)->isRead(), $this->read($pinned)->detail],
        );
    }

    /**
     * An unrelated member the schema refuses never refuses the aggregate, and
     * the pinned entity is validated with the namespaces its aggregate
     * declares, so a prefix an attribute value names still resolves.
     *
     * @return void
     */
    public function testOnlyThePinnedEntityIsSchemaValidated(): void
    {
        $anchors    = [self::idp()->certificate()];
        $aggregate  = self::metadata()->with(['aggregate' => [self::OTHER]])->toXml();
        $invalid    = str_replace('entityID="' . self::OTHER . '"', 'validUntil="tomorrow" entityID="' . self::OTHER . '"', $aggregate);
        $namespaces = 'xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ';
        $declared   = str_replace('<md:EntitiesDescriptor ', '<md:EntitiesDescriptor ' . $namespaces, $aggregate);
        $typed      = self::withMember($declared, self::ENTITY_ID, '<md:Extensions>' . self::entityAttribute('xs:string') . '</md:Extensions>' . self::ROLE);
        $undefined  = self::withMember($declared, self::ENTITY_ID, '<md:Extensions>' . self::entityAttribute('xs:nothing') . '</md:Extensions>' . self::ROLE);

        self::assertSame(self::ENTITY_ID, $this->read(self::signedRoot($invalid, self::idp()->signer()), anchors: $anchors)->entityId());
        self::assertRefused(FailureReason::METADATA_INVALID, 'schema', $this->read($invalid, self::OTHER));
        self::assertSame(self::ENTITY_ID, $this->read(self::signedRoot($typed, self::idp()->signer()), anchors: $anchors)->entityId());
        self::assertRefused(FailureReason::METADATA_INVALID, 'schema', $this->read($undefined));
    }

    /**
     * Only RSA certificates of at least 2048 bits are read, each once: an
     * elliptic curve or a weak one is ignored, and metadata with no usable
     * signing certificate is refused.
     *
     * @return void
     */
    public function testOnlyUsableRsaCertificatesAreReadOnceEach(): void
    {
        $rsa      = self::idp()->certificate();
        $mixed    = [Certificates::ecP256(), $rsa, Certificates::rsa1024(), $rsa, Certificates::distinct(1)];
        $metadata = $this->read(self::metadata()->with(['signing_certificates' => $mixed])->toXml());

        self::assertSame([self::certificate($rsa), self::certificate(Certificates::distinct(1))], $metadata->signingCertificates());
        self::assertRefused(
            FailureReason::METADATA_INVALID,
            'signing_certificate',
            $this->read(self::metadata()->with(['signing_certificates' => [Certificates::ecP256()]])->toXml()),
        );
        self::assertRefused(FailureReason::METADATA_INVALID, 'signing_certificate', $this->read(self::metadata()->with(['signing_certificates' => []])->toXml()));

        $empty = '<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>'
            . '<ds:X509Certificate></ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>';

        self::assertSame([self::certificate($rsa)], $this->read(str_replace('<md:KeyDescriptor', $empty . '<md:KeyDescriptor', self::metadata()->toXml()))->signingCertificates());
    }

    /**
     * A key descriptor's use decides what its certificate is for; one with no
     * use is for both.
     *
     * @return void
     */
    public function testAKeyDescriptorsUseDecidesWhatItsCertificateIsFor(): void
    {
        $signing    = self::idp()->certificate();
        $encryption = Certificates::distinct(2);
        $metadata   = $this->read(self::metadata()->with(['encryption_certificates' => [$encryption]])->toXml());
        $unused     = $this->read(str_replace(' use="signing"', '', self::metadata()->toXml()));

        self::assertSame([self::certificate($signing)], $metadata->signingCertificates());
        self::assertSame([self::certificate($encryption)], $metadata->encryptionCertificates());
        self::assertSame([self::certificate($signing)], $unused->signingCertificates());
        self::assertSame([self::certificate($signing)], $unused->encryptionCertificates());
    }

    /**
     * Rows of `[changes, preferred, binding, url]`: the services the metadata
     * names, the binding the connection uses, and the service chosen.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: ?string, 2: string, 3: string}>
     */
    public static function provideServices(): iterable
    {
        $both = ['post_sso_url' => self::POST_URL];
        $post = ['sso_binding' => FakeSamlMetadata::HTTP_POST, 'sso_url' => self::POST_URL];

        yield from [
            'both, none preferred'           => [$both, null, 'http_redirect', FakeSamlIdentityProvider::SSO_URL],
            'both, redirect preferred'       => [$both, 'http_redirect', 'http_redirect', FakeSamlIdentityProvider::SSO_URL],
            'both, post preferred'           => [$both, 'http_post', 'http_post', self::POST_URL],
            'redirect alone, post preferred' => [[], 'http_post', 'http_redirect', FakeSamlIdentityProvider::SSO_URL],
            'post alone, none preferred'     => [$post, null, 'http_post', self::POST_URL],
            'post alone, unknown preferred'  => [$post, 'artifact', 'http_post', self::POST_URL],
        ];
    }

    /**
     * The service of the binding the connection uses is chosen when the
     * metadata names one, then HTTP-Redirect, then HTTP-POST.
     *
     * @param  array<string, mixed>  $changes
     * @param  ?string  $preferred
     * @param  string  $binding
     * @param  string  $url
     * @return void
     */
    #[DataProvider('provideServices')]
    public function testChoosesTheServiceOfThePreferredBinding(array $changes, ?string $preferred, string $binding, string $url): void
    {
        $metadata = $this->read(self::metadata()->with($changes)->toXml(), binding: $preferred);

        self::assertSame([$binding, $url], [$metadata->ssoBinding(), $metadata->ssoUrl()]);
    }

    /**
     * The first service of a binding is chosen, and a service of any other
     * binding is ignored: with none of the two, the metadata is refused.
     *
     * @return void
     */
    public function testOnlyTheFirstRedirectOrPostServiceIsUsed(): void
    {
        $second   = '<md:SingleSignOnService Binding="' . FakeSamlMetadata::HTTP_REDIRECT . '" Location="https://second.example.test/sso"/>';
        $artifact = ['sso_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact'];
        $two      = str_replace('</md:IDPSSODescriptor>', $second . '</md:IDPSSODescriptor>', self::metadata()->toXml());

        self::assertSame(FakeSamlIdentityProvider::SSO_URL, $this->read($two)->ssoUrl());
        self::assertRefused(FailureReason::METADATA_INVALID, 'sso_service', $this->read(self::metadata()->with($artifact)->toXml()));
        self::assertSame(self::POST_URL, $this->read(self::metadata()->with([...$artifact, 'post_sso_url' => self::POST_URL])->toXml())->ssoUrl());
    }

    /**
     * The entity must have exactly one identity provider descriptor that
     * supports SAML 2.0, wherever the protocol is in its list.
     *
     * @return void
     */
    public function testExactlyOneSaml2IdentityProviderDescriptorIsNeeded(): void
    {
        $xml    = self::metadata()->toXml();
        $saml2  = 'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"';
        $second = '<md:IDPSSODescriptor ' . $saml2 . '>'
            . '<md:SingleSignOnService Binding="' . FakeSamlMetadata::HTTP_POST . '" Location="' . self::POST_URL . '"/>'
            . '</md:IDPSSODescriptor>';

        $saml1 = str_replace($saml2, 'protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol"', $xml);

        self::assertRefused(FailureReason::METADATA_INVALID, 'idp_descriptor', $this->read($saml1));
        self::assertRefused(FailureReason::METADATA_INVALID, 'idp_descriptor', $this->read(str_replace('</md:EntityDescriptor>', $second . '</md:EntityDescriptor>', $xml)));
        self::assertTrue($this->read(str_replace($saml2, 'protocolSupportEnumeration=" urn:example:other  urn:oasis:names:tc:SAML:2.0:protocol "', $xml))->isRead());
    }

    /**
     * The NameID formats are read as text, trimmed, once each, and a comment
     * inside one cannot change it.
     *
     * @return void
     */
    public function testNameIdFormatsAreReadAsTextOnceEach(): void
    {
        $formats = [' urn:example:one ', 'urn:example:two', 'urn:example:one'];
        $xml     = str_replace('urn:example:two', 'urn:example:<!-- a comment -->two', self::metadata()->with(['name_id_formats' => $formats])->toXml());

        self::assertSame(['urn:example:one', 'urn:example:two'], $this->read($xml)->nameIdFormats());
    }

    /**
     * Read metadata shows nothing it holds in a dump or JSON; refused metadata
     * answers no value.
     *
     * @return void
     */
    public function testTheMetadataIsRedactedAndRefusedHoldsNothing(): void
    {
        $metadata = $this->read(self::metadata()->toXml());
        $refused  = $this->read(self::metadata()->toXml(), 'urn:example:nobody');

        self::assertSame(['values' => '[redacted]'], $metadata->__debugInfo());
        self::assertSame('{"values":"[redacted]"}', json_encode($metadata));
        self::assertStringNotContainsString(self::ENTITY_ID, print_r($metadata, true));

        $this->expectExceptionObject(new \LogicException('Refused metadata holds no value.'));

        $refused->entityId();
    }

    /**
     * Metadata that was read refuses to be serialised.
     *
     * @return void
     */
    public function testTheMetadataRefusesSerialization(): void
    {
        $metadata = $this->read(self::metadata()->toXml());

        $this->expectExceptionObject(new \LogicException('A ' . IdpMetadata::class . ' cannot be serialised.'));

        serialize($metadata);
    }

    /**
     * Read the XML with the reader from the container.
     *
     * @param  string  $xml
     * @param  string  $entityId
     * @param  list<string>  $anchors
     * @param  ?string  $binding
     * @return \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata
     */
    private function read(string $xml, string $entityId = self::ENTITY_ID, array $anchors = [], ?string $binding = null): IdpMetadata
    {
        return app(MetadataReader::class)->read($xml, $entityId, $anchors, $binding);
    }

    /**
     * Assert the metadata was refused for the reason by the rule.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $detail
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return void
     */
    private static function assertRefused(FailureReason $reason, string $detail, IdpMetadata $metadata): void
    {
        self::assertFalse($metadata->isRead());
        self::assertSame([$reason, $detail], [$metadata->reason, $metadata->detail]);
    }

    /**
     * Everything read metadata holds, in order.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Saml2\Messages\IdpMetadata  $metadata
     * @return list<mixed>
     */
    private static function values(IdpMetadata $metadata): array
    {
        return [
            $metadata->entityId(),
            $metadata->ssoUrl(),
            $metadata->ssoBinding(),
            $metadata->signingCertificates(),
            $metadata->encryptionCertificates(),
            $metadata->nameIdFormats(),
            $metadata->validUntil(),
        ];
    }

    /**
     * The certificate as the reader answers it: its canonical PEM and its
     * fingerprint.
     *
     * @param  string  $pem
     * @return array{certificate: string, fingerprint: string}
     */
    private static function certificate(string $pem): array
    {
        $masked = MaskedKey::fromCertificate($pem);

        return ['certificate' => (string) $masked->certificate, 'fingerprint' => (string) $masked->fingerprint];
    }

    /**
     * The XML with every `ID` given a prefix, so a copy of an entity repeats
     * none.
     *
     * @param  string  $xml
     * @param  string  $prefix
     * @return string
     */
    private static function renamedIds(string $xml, string $prefix): string
    {
        return str_replace(' ID="_', ' ID="_' . $prefix, $xml);
    }

    /**
     * The XML with its root signed by the signer.
     *
     * @param  string  $xml
     * @param  \SineMacula\Laravel\Sso\Testing\Saml\XmlSigner  $signer
     * @return string
     *
     * @throws \LogicException
     */
    private static function signedRoot(string $xml, XmlSigner $signer): string
    {
        $document = new \DOMDocument;

        self::assertTrue($document->loadXML($xml, LIBXML_NONET));
        self::assertNotNull($document->documentElement);

        $signer->sign($document->documentElement);

        try {
            return (string) $document->saveXML($document->documentElement);
        } catch (\DOMException $exception) {
            throw new \LogicException('The signed document could not be written.', 0, $exception);
        }
    }

    /**
     * A signature, valid in form, as a role descriptor may carry one.
     *
     * @return string
     */
    private static function roleSignature(): string
    {
        return '<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>'
            . '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>'
            . '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>'
            . '<ds:Reference URI=""><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AAAA</ds:DigestValue></ds:Reference>'
            . '</ds:SignedInfo><ds:SignatureValue>AAAA</ds:SignatureValue></ds:Signature>';
    }

    /**
     * The XML with the entity's content replaced by the content given, its own
     * `IDPSSODescriptor` put where the content names its role.
     *
     * @param  string  $xml
     * @param  string  $entityId
     * @param  string  $member
     * @return string
     */
    private static function withMember(string $xml, string $entityId, string $member): string
    {
        $start = strpos($xml, 'entityID="' . $entityId . '"');

        self::assertIsInt($start);

        $role = strpos($xml, '<md:IDPSSODescriptor', $start);
        $end  = strpos($xml, '</md:EntityDescriptor>', $start);

        self::assertIsInt($role);
        self::assertIsInt($end);

        $descriptor = substr($xml, $role, $end - $role);
        $content    = str_replace(self::ROLE, $descriptor, $member);

        return substr($xml, 0, $role) . $content . substr($xml, $end);
    }

    /**
     * A `ContactPerson` of the type.
     *
     * @param  string  $type
     * @return string
     */
    private static function contact(string $type): string
    {
        return '<md:ContactPerson contactType="' . $type . '"><md:EmailAddress>mailto:it@example.edu</md:EmailAddress></md:ContactPerson>';
    }

    /**
     * An `mdui:Logo` of the location, in its `UIInfo`.
     *
     * @param  string  $location
     * @return string
     */
    private static function logo(string $location): string
    {
        return '<mdui:UIInfo xmlns:mdui="urn:oasis:names:tc:SAML:metadata:ui"><mdui:Logo height="16" width="16">' . $location . '</mdui:Logo></mdui:UIInfo>';
    }

    /**
     * An `mdattr:EntityAttributes` whose one value has the `xsi:type`, its
     * prefixes declared only by the aggregate.
     *
     * @param  string  $type
     * @return string
     */
    private static function entityAttribute(string $type): string
    {
        return '<mdattr:EntityAttributes xmlns:mdattr="urn:oasis:names:tc:SAML:metadata:attribute">'
            . '<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="urn:example:category"'
            . ' NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri">'
            . '<saml:AttributeValue xsi:type="' . $type . '">https://refeds.org/category/research-and-scholarship</saml:AttributeValue>'
            . '</saml:Attribute></mdattr:EntityAttributes>';
    }

    /**
     * Valid metadata that is neither an entity nor an aggregate, or the same
     * organisation as a child of an entity.
     *
     * @param  bool  $root
     * @return string
     */
    private static function organization(bool $root = true): string
    {
        return '<md:Organization' . ($root ? ' xmlns:md="' . FakeSamlMetadata::NS_MD . '"' : '') . '>'
            . '<md:OrganizationName xml:lang="en">Example</md:OrganizationName>'
            . '<md:OrganizationDisplayName xml:lang="en">Example</md:OrganizationDisplayName>'
            . '<md:OrganizationURL xml:lang="en">https://example.test</md:OrganizationURL>'
            . '</md:Organization>';
    }

    /**
     * The provider's unsigned metadata.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Saml\FakeSamlMetadata
     */
    private static function metadata(): FakeSamlMetadata
    {
        return self::idp()->metadata();
    }

    /**
     * The provider, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function idp(): FakeSamlIdentityProvider
    {
        return self::$idp ??= new FakeSamlIdentityProvider;
    }

    /**
     * The attacker, made once, with a key the connection never trusts.
     *
     * @return \SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider
     */
    private static function attacker(): FakeSamlIdentityProvider
    {
        return self::$attacker ??= new FakeSamlIdentityProvider('https://attacker.example.test/saml');
    }
}
