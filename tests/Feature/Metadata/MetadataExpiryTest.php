<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Metadata\MetadataExpiry;
use SineMacula\Laravel\Sso\Metadata\SamlRefreshRule;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Keys\Certificates;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for when what a metadata refresh applied stops being used
 * (SSO-2.8): never for a connection no refresh wrote and whose refresh is off;
 * never for a SAML connection that has not opted in, whatever was stamped;
 * otherwise at the earlier of its `validUntil` and its last validated fetch
 * plus the stale limit, or the `validUntil` alone with no limit, and of its
 * JWKS's own validated fetch plus the limit; expired from that instant on; read
 * again by id for a connection given only through its contract.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataExpiry::class)]
#[CoversClass(SamlRefreshRule::class)]
final class MetadataExpiryTest extends TestCase
{
    use UsesConnections;

    /** @var array<string, mixed> The settings of a SAML connection that has opted in to refreshing. */
    private const array OPTED_IN = ['metadata_url' => 'https://idp.example.test/metadata.xml', 'metadata_refresh' => true];

    /** @var \Tests\Fixtures\FixedClock The clock the package reads. */
    private FixedClock $clock;

    /**
     * Bind a fixed clock and create the tables.
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
    }

    /**
     * A connection no refresh wrote never expires, whatever its `validUntil`.
     *
     * @return void
     */
    public function testAConnectionNoRefreshWroteNeverExpires(): void
    {
        $connection = $this->saml(['metadata_valid_until' => $this->clock->now()->subYear()]);

        self::assertNull($this->expiry()->expiresAt($connection));
        self::assertFalse($this->expiry()->isExpired($connection));
    }

    /**
     * With no `validUntil`, what a refresh applied expires the stale limit
     * after its last validated fetch: not a second before, and from that
     * instant on.
     *
     * @return void
     */
    public function testExpiresTheStaleLimitAfterTheLastFetch(): void
    {
        $connection = $this->saml(['metadata_fetched_at' => $this->clock->now()]);

        self::assertSame('2026-12-01T09:30:00+00:00', $this->expiry()->expiresAt($connection)?->toIso8601String());

        $this->clock->advance(2592000 - 1);

        self::assertFalse($this->expiry()->isExpired($connection));

        $this->clock->advance(1);

        self::assertTrue($this->expiry()->isExpired($connection));
    }

    /**
     * The earlier of the `validUntil` and the stale limit decides.
     *
     * @return void
     */
    public function testTheEarlierOfValidUntilAndTheStaleLimitDecides(): void
    {
        $now = $this->clock->now();

        $sooner = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDay()]);
        $later  = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDays(40)]);

        self::assertSame('2026-11-02T09:30:00+00:00', $this->expiry()->expiresAt($sooner)?->toIso8601String());
        self::assertSame('2026-12-01T09:30:00+00:00', $this->expiry()->expiresAt($later)?->toIso8601String());
    }

    /**
     * With no stale limit, only the `validUntil` decides, and with neither
     * nothing expires.
     *
     * @return void
     */
    public function testWithNoStaleLimitOnlyValidUntilDecides(): void
    {
        config()->set('sso.metadata.stale_limit_seconds', 0);

        $now = $this->clock->now();

        $dated = $this->saml(['metadata_fetched_at' => $now, 'metadata_valid_until' => $now->addDay()]);

        self::assertSame('2026-11-02T09:30:00+00:00', $this->expiry()->expiresAt($dated)?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($this->saml(['metadata_fetched_at' => $now])));
    }

    /**
     * Rows of `[validated, valid until, stale limit, expiry, expired]`: when a
     * fetched document was validated, its `validUntil`, the stale limit, when
     * it expires and whether it has by now.
     *
     * @return iterable<string, array{0: string, 1: ?string, 2: int, 3: ?string, 4: bool}>
     */
    public static function provideValidatedDocuments(): iterable
    {
        yield from [
            'validated now'                      => ['2026-11-01T09:30:00Z', null, 2592000, '2026-12-01T09:30:00+00:00', false],
            'validated a limit less a second'    => ['2026-10-02T09:30:01Z', null, 2592000, '2026-11-01T09:30:01+00:00', false],
            'validated exactly a limit ago'      => ['2026-10-02T09:30:00Z', null, 2592000, '2026-11-01T09:30:00+00:00', true],
            'a valid until earlier, passed'      => ['2026-11-01T09:30:00Z', '2026-11-01T09:30:00Z', 2592000, '2026-11-01T09:30:00+00:00', true],
            'a valid until a second off'         => ['2026-11-01T09:30:00Z', '2026-11-01T09:30:01Z', 2592000, '2026-11-01T09:30:01+00:00', false],
            'the stale limit before valid until' => ['2026-10-02T09:30:00Z', '2027-01-01T00:00:00Z', 2592000, '2026-11-01T09:30:00+00:00', true],
            'no limit and no valid until'        => ['2025-01-01T00:00:00Z', null, 0, null, false],
        ];
    }

    /**
     * The expiry of a fetched document, as a refresh judges it at commit, is
     * the earlier of its `validUntil` and the moment it was validated plus the
     * stale limit, and it has expired from that instant on.
     *
     * @param  string  $validated
     * @param  ?string  $validUntil
     * @param  int  $limit
     * @param  ?string  $expiry
     * @param  bool  $expired
     * @return void
     */
    #[DataProvider('provideValidatedDocuments')]
    public function testADocumentExpiresFromItsValidation(string $validated, ?string $validUntil, int $limit, ?string $expiry, bool $expired): void
    {
        config()->set('sso.metadata.stale_limit_seconds', $limit);

        $until = $validUntil === null ? null : CarbonImmutable::parse($validUntil);
        $at    = CarbonImmutable::parse($validated);

        self::assertSame([$expiry, $expired], [$this->expiry()->expiryOf($until, $at)?->toIso8601String(), $this->expiry()->hasExpired($until, $at)]);
    }

    /**
     * An OIDC connection's JWKS counts from its own validated fetch: the
     * earlier of it and the discovery document's decides, the stale limit after
     * each, and a JWKS refetched since moves only its own; with nothing
     * fetched, nothing expires.
     *
     * @return void
     */
    public function testTheJwksExpiresFromItsOwnFetch(): void
    {
        $now = $this->clock->now();

        $older  = $this->makeConnection(['protocol' => 'oidc', 'metadata_fetched_at' => $now, 'jwks_fetched_at' => $now->subDays(2)]);
        $newer  = $this->makeConnection(['protocol' => 'oidc', 'metadata_fetched_at' => $now->subDays(2), 'jwks_fetched_at' => $now]);
        $never  = $this->makeConnection(['protocol' => 'oidc', 'jwks' => '[]']);
        $nojwks = $this->makeConnection(['protocol' => 'oidc', 'metadata_fetched_at' => $now]);

        self::assertSame('2026-11-29T09:30:00+00:00', $this->expiry()->expiresAt($older)?->toIso8601String());
        self::assertSame('2026-11-29T09:30:00+00:00', $this->expiry()->expiresAt($newer)?->toIso8601String());
        self::assertNull($this->expiry()->expiresAt($never));
        self::assertSame('2026-12-01T09:30:00+00:00', $this->expiry()->expiresAt($nojwks)?->toIso8601String());

        $this->clock->advance(2592000 - 2 * 86400 - 1);

        self::assertFalse($this->expiry()->isExpired($older));

        $this->clock->advance(1);

        self::assertTrue($this->expiry()->isExpired($older));

        config()->set('sso.metadata.stale_limit_seconds', 0);

        self::assertNull($this->expiry()->expiresAt($older));
    }

    /**
     * Rows of `[seconds fetched ago, refresh, expired]`: a JWKS a refetch
     * stamped on a connection no refresh has written, around the limit, and
     * whether its refresh is on.
     *
     * @return iterable<string, array{0: int, 1: mixed, 2: bool}>
     */
    public static function provideUnrefreshedKeys(): iterable
    {
        yield from [
            'refresh on, a second under the limit'  => [2592000 - 1, true, false],
            'refresh on, at the limit'              => [2592000, true, true],
            'refresh on, a second over the limit'   => [2592000 + 1, true, true],
            'refresh off, a second under the limit' => [2592000 - 1, false, false],
            'refresh off, at the limit'             => [2592000, false, true],
            'refresh off, over the limit'           => [2592000 + 1, false, true],
            'refresh not true, over the limit'      => [2592000 + 1, 'true', true],
            'no refresh setting, over the limit'    => [2592000 + 1, null, true],
        ];
    }

    /**
     * Keys count from their own validated fetch whatever the refresh's switch
     * says, no refresh having written the connection: turning the schedule off
     * never means unlimited trust.
     *
     * @param  int  $seconds
     * @param  mixed  $refresh
     * @param  bool  $expired
     * @return void
     */
    #[DataProvider('provideUnrefreshedKeys')]
    public function testKeysAgeOutWhateverTheRefreshsSwitchSays(int $seconds, mixed $refresh, bool $expired): void
    {
        $fetched    = $this->clock->now()->subSeconds($seconds);
        $connection = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['metadata_refresh' => $refresh], 'jwks_fetched_at' => $fetched]);

        self::assertSame($expired, $this->expiry()->isExpired($connection));
        self::assertSame($fetched->addSeconds(2592000)->toIso8601String(), $this->expiry()->expiresAt($connection)?->toIso8601String());
    }

    /**
     * Rows of `[anchored, settings, expiry]`: what a fetch stamped on a SAML
     * connection expires by: the stale limit where it holds a deadline, and
     * never otherwise.
     *
     * @return iterable<string, array{0: bool, 1: array<string, mixed>, 2: ?string}>
     */
    public static function provideSamlDeadlines(): iterable
    {
        $url = ['metadata_url' => 'https://idp.example.test/metadata.xml'];

        yield from [
            'an anchor, unset'         => [true, $url, '2026-12-01T09:30:00+00:00'],
            'an anchor, true'          => [true, [...$url, 'metadata_refresh' => true], '2026-12-01T09:30:00+00:00'],
            'an anchor, false'         => [true, [...$url, 'metadata_refresh' => false], '2026-12-01T09:30:00+00:00'],
            'no anchor, unset'         => [false, $url, null],
            'no anchor, true'          => [false, [...$url, 'metadata_refresh' => true], '2026-12-01T09:30:00+00:00'],
            'no anchor, false'         => [false, [...$url, 'metadata_refresh' => false], null],
            'an anchor, unset, no URL' => [true, [], null],
            'an anchor, false, no URL' => [true, ['metadata_refresh' => false], null],
            'no anchor, unset, no URL' => [false, [], null],
            'an anchor, an http URL'   => [true, ['metadata_url' => 'http://idp.example.test/metadata.xml'], null],
        ];
    }

    /**
     * A document stamped now holds the deadline the anchor and the switch give
     * it, and one with a `validUntil` long past has expired only where a
     * deadline holds.
     *
     * @param  bool  $anchored
     * @param  array<string, mixed>  $settings
     * @param  ?string  $expiry
     * @return void
     */
    #[DataProvider('provideSamlDeadlines')]
    public function testASamlDocumentHoldsTheDeadlineItsRefreshGivesIt(bool $anchored, array $settings, ?string $expiry): void
    {
        $connection = $this->saml(['metadata_fetched_at' => $this->clock->now()], $settings);
        $past       = $this->saml(['metadata_fetched_at' => $this->clock->now()->subYear(), 'metadata_valid_until' => $this->clock->now()->subMonth()], $settings);

        if ($anchored) {
            $this->anchor($connection);
            $this->anchor($past);
        }

        self::assertSame($expiry, $this->expiry()->expiresAt($connection)?->toIso8601String());
        self::assertSame($expiry !== null, $this->expiry()->isExpired($past));
    }

    /**
     * A SAML document counts from its own validated fetch with its refresh off
     * too, while it has an anchor.
     *
     * @return void
     */
    public function testADocumentAgesOutWithItsRefreshOff(): void
    {
        $fetched    = $this->clock->now()->subSeconds(2592000);
        $connection = $this->saml(['metadata_fetched_at' => $fetched], ['metadata_url' => self::OPTED_IN['metadata_url'], 'metadata_refresh' => false]);

        $this->anchor($connection);

        self::assertTrue($this->expiry()->isExpired($connection));

        config()->set('sso.features.metadata_refresh', false);

        self::assertTrue($this->expiry()->isExpired($connection));
    }

    /**
     * A connection with nothing fetched yet has no deadline, its settings and
     * keys saved by hand, however old the row and whatever its switch says.
     *
     * @return void
     */
    public function testNothingFetchedHasNoDeadline(): void
    {
        $handSaved = $this->makeConnection([
            'protocol'   => 'oidc',
            'jwks'       => '[{"kty":"RSA"}]',
            'settings'   => ['issuer' => 'https://op.example.test', 'metadata_refresh' => true],
            'created_at' => $this->clock->now()->subYears(5),
        ]);

        self::assertNull($this->expiry()->expiresAt($handSaved));
        self::assertFalse($this->expiry()->isExpired($handSaved));

        $this->clock->advance(10 * 2592000);

        self::assertFalse($this->expiry()->isExpired($handSaved));
    }

    /**
     * With no stale limit, keys never age out, whatever the refresh; and a
     * connection whose refresh is on but holds no fetched keys never expires.
     *
     * @return void
     */
    public function testKeysHaveNoLimitWithNoStaleLimit(): void
    {
        $unfetched = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['metadata_refresh' => true]]);

        self::assertNull($this->expiry()->expiresAt($unfetched));

        config()->set('sso.metadata.stale_limit_seconds', 0);

        $connection = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['metadata_refresh' => true], 'jwks_fetched_at' => $this->clock->now()->subYear()]);

        self::assertNull($this->expiry()->expiresAt($connection));
    }

    /**
     * A connection given only through its contract is read again by its id; one
     * that is gone never expires.
     *
     * @return void
     */
    public function testAConnectionGivenThroughItsContractIsReadAgain(): void
    {
        $connection = $this->saml(['metadata_fetched_at' => $this->clock->now()->subDays(31)]);

        self::assertTrue($this->expiry()->isExpired(new IdentifiedConnection($connection->id)));
        self::assertFalse($this->expiry()->isExpired(new IdentifiedConnection('01jbgoneconnection00000000')));
    }

    /**
     * The expiry, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\MetadataExpiry
     */
    private function expiry(): MetadataExpiry
    {
        return app(MetadataExpiry::class);
    }

    /**
     * A SAML connection with the attributes and settings given, opted in to
     * refreshing unless they say otherwise.
     *
     * @param  array<string, mixed>  $attributes
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(array $attributes, array $settings = self::OPTED_IN): Connection
    {
        return $this->makeConnection(['protocol' => 'saml2', 'settings' => $settings, ...$attributes]);
    }

    /**
     * Give the connection a metadata signing anchor.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return void
     */
    private function anchor(Connection $connection): void
    {
        $masked = MaskedKey::fromCertificate(Certificates::distinct(0));

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::METADATA_SIGNING,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'fingerprint'   => $masked->fingerprint,
        ])->save();
    }
}
