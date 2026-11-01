<?php

declare(strict_types = 1);

namespace Tests\Feature\Console;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Console\RefreshMetadataCommand;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Keys\Enums\KeyType;
use SineMacula\Laravel\Sso\Keys\Enums\KeyUse;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\ConnectionKey;
use SineMacula\Laravel\Sso\Secrets\MaskedKey;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for `sso:metadata:refresh` (SSO-2.8, SSO-11.12): it refreshes
 * every due connection and prints one line, the count of each outcome, and no
 * URL, entity id or value of a connection; it exits 0 whatever the outcomes, a
 * second run changes and refreshes nothing, and a run that stopped on an
 * exception exits 1 naming the exception's class alone.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RefreshMetadataCommand::class)]
final class RefreshMetadataCommandTest extends TestCase
{
    use UsesConnections, UsesFlowTables;

    /** @var string The summary of a run that refreshed nothing. */
    private const string NOTHING = 'Metadata refreshed: refreshed 0, failed 0, conflict 0, in_progress 0, skipped 0, refused 0';

    /** @var string The URL the working provider serves its metadata at. */
    private const string URL = 'https://idp.example.test/metadata.xml';

    /** @var string The URL the failing provider serves nothing at. */
    private const string FAILING_URL = 'https://down.example.test/metadata.xml';

    /** @var ?\SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider The provider, made once. */
    private static ?FakeSamlIdentityProvider $idp = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher the refresh fetches through. */
    private FakeFetcher $fetcher;

    /**
     * Bind a fixed clock and a fake fetcher, switch SAML and the refresh on,
     * and create the tables.
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

        config()->set('sso.features.saml2', true);
        config()->set('sso.features.metadata_refresh', true);

        $this->createConnectionTables();
        $this->createFlowTables();
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropFlowTables();
        $this->dropConnectionTables();

        parent::tearDown();
    }

    /**
     * With nothing due, the run prints the summary alone and passes.
     *
     * @return void
     */
    public function testWithNothingDuePrintsTheSummaryAlone(): void
    {
        self::assertSame([0, [self::NOTHING]], $this->refreshFromConsole());
    }

    /**
     * A run counts each outcome, prints nothing of any connection, and passes
     * though a refresh failed; a second run refreshes nothing.
     *
     * @return void
     */
    public function testCountsEachOutcomeAndPrintsNoValue(): void
    {
        $this->saml(self::URL);
        $this->saml(self::FAILING_URL);

        $this->fetcher->respond(self::URL, FetchResult::fetched(200, [], self::idp()->metadata()->toXml()));
        $this->fetcher->respond(self::FAILING_URL, FetchResult::failed());

        [$code, $output] = $this->refreshFromConsole();

        self::assertSame([0, ['Metadata refreshed: refreshed 1, failed 1, conflict 0, in_progress 0, skipped 0, refused 0']], [$code, $output]);

        foreach ([self::URL, self::FAILING_URL, FakeSamlIdentityProvider::ENTITY_ID, FakeSamlIdentityProvider::SSO_URL] as $value) {
            self::assertStringNotContainsString($value, implode("\n", $output));
        }

        self::assertSame([0, [self::NOTHING]], $this->refreshFromConsole());
        self::assertCount(2, $this->fetcher->requests());
    }

    /**
     * A run that stopped on an exception exits 1 and names its class alone.
     *
     * @return void
     */
    public function testARunThatStoppedNamesTheExceptionsClassAlone(): void
    {
        $this->saml(self::URL);

        $result = DB::connection(StorageConnection::name())->transaction(fn (): array => $this->refreshFromConsole());

        self::assertSame([1, ['The metadata refresh stopped on LogicException.']], $result);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Run the command, and answer its exit code and its non-empty lines.
     *
     * @return array{0: int, 1: list<string>}
     */
    private function refreshFromConsole(): array
    {
        $code   = Artisan::call('sso:metadata:refresh');
        $output = array_values(array_filter(explode("\n", Artisan::output()), static fn (string $line): bool => trim($line) !== ''));

        return [$code, array_map(trim(...), $output)];
    }

    /**
     * A refreshing SAML connection fetching from the URL, trusting the
     * provider's certificate.
     *
     * @param  string  $url
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function saml(string $url): Connection
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'enabled' => true, 'settings' => [
            'idp_entity_id'    => FakeSamlIdentityProvider::ENTITY_ID,
            'sso_url'          => FakeSamlIdentityProvider::SSO_URL,
            'sso_binding'      => 'http_redirect',
            'metadata_url'     => $url,
            'metadata_refresh' => true,
        ]]);

        $masked = MaskedKey::fromCertificate(self::idp()->certificate());

        (new ConnectionKey)->forceFill([
            'connection_id' => $connection->id,
            'use'           => KeyUse::IDP_SIGNING,
            'state'         => null,
            'key_type'      => KeyType::RSA,
            'key_bits'      => 2048,
            'certificate'   => $masked->certificate,
            'public_key'    => $masked->publicKey,
            'private_key'   => null,
            'fingerprint'   => $masked->fingerprint,
        ])->save();

        return $connection;
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
}
