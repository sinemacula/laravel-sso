<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\Enums\FetchStatus;
use SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome;
use SineMacula\Laravel\Sso\Metadata\FetchedMetadata;
use SineMacula\Laravel\Sso\Metadata\MetadataRefresher;
use SineMacula\Laravel\Sso\Metadata\MetadataSources;
use SineMacula\Laravel\Sso\Metadata\OidcMetadataSource;
use SineMacula\Laravel\Sso\Metadata\RefreshResult;
use SineMacula\Laravel\Sso\Metadata\SamlMetadataSource;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use Tests\Concerns\UsesConnections;
use Tests\Fixtures\Clients;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for the sources the shared refresh machinery refreshes through
 * (SSO-2.8, SSO-11.12): one per package protocol and none for a protocol an
 * application registered, whose connection is never due and an administrator's
 * refresh of which is `feature_disabled`, with nothing claimed or fetched; and
 * what a fetch found, holding its document out of every dump.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataSources::class)]
#[CoversClass(FetchedMetadata::class)]
final class MetadataSourcesTest extends TestCase
{
    use UsesConnections;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher, which answers nothing. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fetcher, turn the refresh on and create the
     * tables.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher = new FakeFetcher;

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        config()->set('sso.features.oidc', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->usePackageTables();
    }

    /**
     * Each package protocol has its source, and another protocol none.
     *
     * @return void
     */
    public function testEachPackageProtocolHasItsSource(): void
    {
        $sources = app(MetadataSources::class);

        self::assertSame(['saml2', 'oidc'], $sources->protocols());
        self::assertInstanceOf(SamlMetadataSource::class, $sources->for('saml2'));
        self::assertInstanceOf(OidcMetadataSource::class, $sources->for('oidc'));
        self::assertNull($sources->for('cas'));
        self::assertNull($sources->for('OIDC'));
    }

    /**
     * A connection whose protocol has no source is never due, and an
     * administrator's refresh of one is `feature_disabled`, with nothing
     * claimed or fetched.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAProtocolWithNoSourceDoesNotRefresh(): void
    {
        $connection = $this->makeConnection(['protocol' => 'cas', 'settings' => ['metadata_refresh' => true]]);
        $refresher  = app(MetadataRefresher::class);
        $actor      = new ActingIdentity('App\Models\User', '1');

        self::assertSame([], $refresher->dueConnectionIds());
        self::assertSame(RefreshOutcome::SKIPPED, $refresher->refreshQueued($connection->id, Clients::browser())->outcome);
        self::assertSame(
            [RefreshOutcome::REFUSED, FailureReason::FEATURE_DISABLED],
            self::outcome($refresher->refreshNow('tenant-1', $connection->id, $actor, Clients::browser())),
        );
        self::assertNull($connection->fresh()?->metadata_claim_token);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * What a fetch found holds its document, when it read one, out of every
     * dump, and refuses to be serialised.
     *
     * @return void
     */
    public function testWhatAFetchFoundHidesItsDocument(): void
    {
        $document = (object) ['secret' => 'secret-document'];
        $read     = FetchedMetadata::read($document, CarbonImmutable::parse('2026-11-01T09:30:00Z'));
        $refused  = FetchedMetadata::refused(FailureReason::JWKS_INVALID, FetchStatus::FETCHED);

        self::assertSame([true, $document, null, FetchStatus::FETCHED], [$read->isRead(), $read->document(), $read->reason, $read->fetchStatus]);
        self::assertSame([false, null, FailureReason::JWKS_INVALID, null], [$refused->isRead(), $refused->document(), $refused->reason, $refused->validatedAt]);
        self::assertSame(['fetch_status' => 'fetched', 'document' => '[redacted]', 'validated_at' => '2026-11-01T09:30:00+00:00', 'reason' => null], $read->__debugInfo());
        self::assertSame(['fetch_status' => 'fetched', 'document' => null, 'validated_at' => null, 'reason' => 'jwks_invalid'], $refused->__debugInfo());
        self::assertStringNotContainsString('secret-document', print_r($read, true));

        $serialised = 'O:' . strlen(FetchedMetadata::class) . ':"' . FetchedMetadata::class . '":0:{}';

        self::assertSame(
            ['Fetched metadata cannot be serialised.', 'Fetched metadata cannot be unserialised.'],
            [self::refusal(static fn (): string => serialize($read)), self::refusal(static fn (): mixed => unserialize($serialised))],
        );
    }

    /**
     * The message of the `LogicException` the work throws, or none.
     *
     * @param  \Closure(): mixed  $work
     * @return ?string
     */
    private static function refusal(\Closure $work): ?string
    {
        try {
            $work();
        } catch (\LogicException $exception) {
            return $exception->getMessage();
        }

        return null;
    }

    /**
     * A refresh's outcome and reason.
     *
     * @param  \SineMacula\Laravel\Sso\Metadata\RefreshResult  $result
     * @return array{0: \SineMacula\Laravel\Sso\Metadata\Enums\RefreshOutcome, 1: ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason}
     */
    private static function outcome(RefreshResult $result): array
    {
        return [$result->outcome, $result->reason];
    }
}
