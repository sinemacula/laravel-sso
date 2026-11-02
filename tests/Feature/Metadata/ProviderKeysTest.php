<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Fetching\FetchRequest;
use SineMacula\Laravel\Sso\Fetching\FetchResult;
use SineMacula\Laravel\Sso\Metadata\ProviderKeys;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Testing\FakeFetcher;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeTokenEndpoint;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\CapturesLogs;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Protocols\IdentifiedConnection;
use Tests\TestCase;

/**
 * Feature tests for the key an ID token is checked with (SSO-7.3): chosen from
 * the JWKS stored with its connection, read on the write connection whether the
 * connection is given as a row or through its contract, admitted again for the
 * allow-list. Only a selection that is unknown refetches, once: a refused one
 * never fetches, a `kid` the refetch did not bring never falls back to a key
 * without one, and how each refetch ended is logged with its reason and the
 * fetch's status alone. It also pins what an update of the issuer or the JWKS
 * URI clears.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderKeys::class)]
final class ProviderKeysTest extends TestCase
{
    use CapturesLogs, UsesConnections, UsesFlowTables;

    /** @var string The provider's issuer. */
    private const string ISSUER = FakeOpenIdProvider::ISSUER;

    /** @var string What a failed refetch is logged as. */
    private const string FAILED = 'sso.oidc.jwks_refetch_failed';

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key, generated once. */
    private static ?FakeSigningKey $key = null;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The provider's next key, generated once. */
    private static ?FakeSigningKey $next = null;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFetcher The fetcher a refetch fetches through. */
    private FakeFetcher $fetcher;

    /** @var \SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider The provider a refetch reads. */
    private FakeOpenIdProvider $provider;

    /**
     * Bind a fixed clock and a fake fetcher serving the provider, create the
     * tables and capture logs.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->fetcher  = new FakeFetcher;
        $this->provider = (new FakeOpenIdProvider(self::ISSUER, self::key()))->serve($this->fetcher);

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Fetcher::class, $this->fetcher);

        $this->createConnectionTables();
        $this->createFlowTables();
        $this->captureLogs();
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
     * The key is chosen from the stored JWKS by its `kid`, whichever way the
     * connection is given, with nothing fetched or logged.
     *
     * @return void
     */
    public function testTheKeyIsChosenFromTheStoredJwks(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $found = $this->keys()->select($connection, self::token('rsa-1'), self::rs256());

        self::assertSame([KeySelectionOutcome::FOUND, 'rsa-1'], [$found->outcome, $found->key?->keyId()]);
        self::assertSame(KeySelectionOutcome::FOUND, $this->keys()->select(new IdentifiedConnection($connection->id), self::token('rsa-1'), self::rs256())->outcome);
        self::assertSame([], $this->capturedLogRecords());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A connection that is gone holds no key and has nothing to refetch.
     *
     * @return void
     */
    public function testAConnectionThatIsGoneHoldsNoKey(): void
    {
        $gone = new IdentifiedConnection('01jbgoneconnection00000000');

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->keys()->select($gone, self::token('rsa-1'), self::rs256())->outcome);
        self::assertSame([], $this->capturedLogRecords());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[token, allow-list]`: a selection that is refused, the stored
     * key being there or not.
     *
     * @return iterable<string, array{0: \Closure(): string, 1: list<string>}>
     */
    public static function provideRefusedSelections(): iterable
    {
        yield from [
            'alg none'                    => [static fn (): string => JwsSigner::hmac(['alg' => 'none', 'kid' => 'other'], ['sub' => 'a'], 'x'), ['RS256']],
            'HS256 with the public key'   => [static fn (): string => JwsSigner::hmac(['alg' => 'HS256', 'kid' => 'rsa-1'], ['sub' => 'a'], self::key()->publicKeyPem), ['RS256']],
            'HS256 with an unknown kid'   => [static fn (): string => JwsSigner::hmac(['alg' => 'HS256', 'kid' => 'other'], ['sub' => 'a'], 'x'), ['RS256']],
            'RS256 off the allow-list'    => [static fn (): string => self::tokenText('rsa-1'), ['PS256']],
            'an unknown kid off the list' => [static fn (): string => self::tokenText('other'), ['PS256']],
        ];
    }

    /**
     * A selection that is refused never fetches: only an unknown one does.
     *
     * @param  \Closure(): string  $token
     * @param  list<string>  $allowed
     * @return void
     */
    #[DataProvider('provideRefusedSelections')]
    public function testARefusedSelectionNeverFetches(\Closure $token, array $allowed): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $parsed     = CompactToken::parse($token(), 16384);

        self::assertInstanceOf(CompactToken::class, $parsed);
        self::assertSame(KeySelectionOutcome::REFUSED, $this->keys()->select($connection, $parsed, AlgorithmAllowList::of($allowed))->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * An unknown `kid` refetches once and finds the key the provider has just
     * published, and how it ended is logged as information.
     *
     * @return void
     */
    public function testAnUnknownKidRefetchesAndFindsTheKey(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->publish(self::next());

        $found = $this->keys()->select($connection, self::token('rsa-2'), self::rs256());

        self::assertSame([KeySelectionOutcome::FOUND, 'rsa-2'], [$found->outcome, $found->key?->keyId()]);
        self::assertCount(1, $this->fetcher->requests());
        self::assertSame(self::ISSUER . '/jwks', $this->fetcher->requests()[0]->url);
        self::assertSame([
            ['info', 'sso.oidc.jwks_refetch_refreshed', ['reason' => null, 'fetch_status' => 'fetched']],
        ], $this->logged());
    }

    /**
     * A `kid` the refetch did not bring stays unknown after one fetch: it never
     * falls back to the key without a `kid` it brought, and a select never
     * refetches twice.
     *
     * @return void
     */
    public function testAnUnknownKidNeverFallsBackToAKeyWithoutOne(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->unpublish('rsa-1')->publish(self::key()->withKid(null));

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->keys()->select($connection, self::token('other'), self::rs256())->outcome);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * Rows of `[keys the JWKS gives, outcome]`: a token with no `kid` after a
     * refetch, none stored before.
     *
     * @return iterable<string, array{0: list<string>, 1: \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome}>
     */
    public static function provideKeysWithoutAKid(): iterable
    {
        yield from [
            'one admissible key'  => [['rsa-1'], KeySelectionOutcome::FOUND],
            'two admissible keys' => [['rsa-1', 'rsa-2'], KeySelectionOutcome::REFUSED],
        ];
    }

    /**
     * A token with no `kid` and no admissible key stored refetches, and is then
     * chosen by the same rule.
     *
     * @param  list<string>  $kids
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome  $outcome
     * @return void
     */
    #[DataProvider('provideKeysWithoutAKid')]
    public function testNoKidAndNoAdmissibleKeyRefetches(array $kids, KeySelectionOutcome $outcome): void
    {
        $connection = $this->connection(null);

        if ($kids === ['rsa-1', 'rsa-2']) {
            $this->provider->publish(self::next());
        }

        self::assertSame($outcome, $this->keys()->select($connection, self::token(null), self::rs256())->outcome);
        self::assertCount(1, $this->fetcher->requests());
    }

    /**
     * A token with no `kid` and exactly one admissible key stored is chosen
     * with no fetch, and with two is refused with no fetch.
     *
     * @return void
     */
    public function testNoKidIsChosenFromTheStoredKeysWithNoFetch(): void
    {
        $one = $this->connection(self::stored([self::key()]));
        $two = $this->connection(self::stored([self::key(), self::next()]));

        self::assertSame(KeySelectionOutcome::FOUND, $this->keys()->select($one, self::token(null), self::rs256())->outcome);
        self::assertSame(KeySelectionOutcome::REFUSED, $this->keys()->select($two, self::token(null), self::rs256())->outcome);

        $this->fetcher->assertNothingFetched();
    }

    /**
     * Rows of `[answer the JWKS gives, level, message, context]`: how a refetch
     * that did not find the key is logged.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Fetching\FetchResult, 1: string, 2: string, 3: array<string, mixed>}>
     */
    public static function provideFailedRefetches(): iterable
    {
        yield from [
            'a fetch refused' => [FetchResult::refused(), 'warning', self::FAILED, ['reason' => 'fetch_refused', 'fetch_status' => 'refused']],
            'a fetch failed'  => [FetchResult::failed(), 'warning', self::FAILED, ['reason' => 'fetch_failed', 'fetch_status' => 'failed']],
            'a server error'  => [FetchResult::fetched(500, [], 'detail'), 'warning', self::FAILED, ['reason' => 'fetch_failed', 'fetch_status' => 'fetched']],
            'a JWKS refused'  => [FetchResult::fetched(200, [], '{"keys":[]}'), 'warning', self::FAILED, ['reason' => 'jwks_invalid', 'fetch_status' => 'fetched']],
        ];
    }

    /**
     * A failed refetch is logged as a warning with its reason and the fetch's
     * status alone, never the URL, the body or a key, and the key stays
     * unknown.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchResult  $response
     * @param  string  $level
     * @param  string  $message
     * @param  array<string, mixed>  $context
     * @return void
     */
    #[DataProvider('provideFailedRefetches')]
    public function testAFailedRefetchIsLogged(FetchResult $response, string $level, string $message, array $context): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->respond('jwks', $response);

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->keys()->select($connection, self::token('rsa-2'), self::rs256())->outcome);
        self::assertSame([[$level, $message, $context]], $this->logged());

        $this->assertNothingLoggedContains('op.example.test', 'detail', self::modulusOf(self::key()));
    }

    /**
     * A refetch that lost to a change is logged as a warning, and the winner's
     * keys are selected from.
     *
     * @return void
     */
    public function testALostRefetchIsLoggedAndTheWinnersKeysSelected(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $winner     = self::stored([self::next()]);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection, $winner): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->update(['jwks' => $winner, 'jwks_version' => 7]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $found = $this->keys()->select($connection, self::token('rsa-2'), self::rs256());

        self::assertSame([KeySelectionOutcome::FOUND, 'rsa-2'], [$found->outcome, $found->key?->keyId()]);
        self::assertSame([['warning', 'sso.oidc.jwks_refetch_conflict', ['reason' => 'metadata_conflict', 'fetch_status' => 'fetched']]], $this->logged());
    }

    /**
     * A refetch that lost to a change of anything but trust, leaving no key for
     * the token, stays unknown.
     *
     * @return void
     */
    public function testARefetchThatLostToAKeyWriteStaysUnknown(): void
    {
        $connection = $this->connection(self::stored([self::key()]));

        $this->provider->respond('jwks', function (FetchRequest $request) use ($connection): FetchResult {
            unset($request);

            Connection::query()->whereKey($connection->id)->update(['jwks_version' => 7]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->keys()->select($connection, self::token('rsa-2'), self::rs256())->outcome);
    }

    /**
     * A refetch that lost to a trust change, leaving no key for the token, is
     * overtaken; as is one whose connection was deleted meanwhile; and a key
     * the winner left stored is still found.
     *
     * @return void
     */
    public function testARefetchOvertakenByATrustChangeSaysSo(): void
    {
        $changed = $this->connection(self::stored([self::key()]));
        $deleted = $this->connection(self::stored([self::key()]));
        $found   = $this->connection(self::stored([self::key()]));
        $moved   = ['trust_version' => 2];

        $this->provider->respond('jwks', function (FetchRequest $request) use ($changed, $moved): FetchResult {
            unset($request);

            Connection::query()->whereKey($changed->id)->update($moved);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        $overtaken = $this->keys()->select($changed, self::token('rsa-2'), self::rs256());

        self::assertSame([KeySelectionOutcome::OVERTAKEN, null, true, false], [$overtaken->outcome, $overtaken->key, $overtaken->isOvertaken(), $overtaken->isFound()]);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($deleted): FetchResult {
            unset($request);

            Connection::query()->whereKey($deleted->id)->delete();

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        self::assertSame(KeySelectionOutcome::OVERTAKEN, $this->keys()->select($deleted, self::token('rsa-2'), self::rs256())->outcome);

        $winner = self::stored([self::next()]);

        $this->provider->respond('jwks', function (FetchRequest $request) use ($found, $winner, $moved): FetchResult {
            unset($request);

            Connection::query()->whereKey($found->id)->update(['jwks' => $winner, ...$moved]);

            return FakeTokenEndpoint::json(200, $this->provider->jwks());
        });

        self::assertSame(KeySelectionOutcome::FOUND, $this->keys()->select($found, self::token('rsa-2'), self::rs256())->outcome);
    }

    /**
     * A refetch the cooldown holds fetches nothing, reads what is stored now,
     * and is logged as information with neither a reason nor a status.
     *
     * @return void
     */
    public function testACooldownIsLoggedAndWhatIsStoredSelected(): void
    {
        $connection = $this->connection(self::stored([self::key()]), ['jwks_refetch_at' => app(Clock::class)->now()->addSecond()]);

        self::assertSame(KeySelectionOutcome::UNKNOWN, $this->keys()->select($connection, self::token('rsa-2'), self::rs256())->outcome);
        self::assertSame([['info', 'sso.oidc.jwks_refetch_cooling_down', ['reason' => null, 'fetch_status' => null]]], $this->logged());

        $this->fetcher->assertNothingFetched();
    }

    /**
     * A selection that would refetch inside a transaction refuses, with nothing
     * claimed or fetched; one that needs no refetch runs inside one.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testARefetchRefusesToRunInsideATransaction(): void
    {
        $connection = $this->connection(self::stored([self::key()]));
        $database   = DB::connection(StorageConnection::name());

        $database->beginTransaction();

        try {
            self::assertSame(KeySelectionOutcome::FOUND, $this->keys()->select($connection, self::token('rsa-1'), self::rs256())->outcome);

            $this->keys()->select($connection, self::token('rsa-2'), self::rs256());

            self::fail('A refetch ran inside a transaction.');
        } catch (\LogicException $exception) {
            self::assertSame('A JWKS refetch runs outside any transaction on the storage connection, since it fetches before it writes.', $exception->getMessage());
        } finally {
            $database->rollBack();
        }

        $this->fetcher->assertNothingFetched();

        self::assertNull(Connection::query()->findOrFail($connection->id)->jwks_refetch_at);
    }

    /**
     * Rows of `[protocol, settings changed, what is cleared beside the keys]`.
     *
     * @return iterable<string, array{0: string, 1: list<string>, 2: bool, 3: bool}>
     */
    public static function provideResets(): iterable
    {
        yield from [
            'no setting'                => ['oidc', [], false, false],
            'another setting'           => ['oidc', ['token_endpoint', 'client_id'], false, false],
            'the issuer'                => ['oidc', ['issuer'], true, true],
            'the JWKS URI'              => ['oidc', ['jwks_uri'], true, false],
            'the issuer and JWKS URI'   => ['oidc', ['issuer', 'jwks_uri'], true, true],
            'the issuer among others'   => ['oidc', ['client_id', 'issuer'], true, true],
            'an issuer of another kind' => ['saml2', ['issuer', 'jwks_uri'], false, false],
        ];
    }

    /**
     * An update of the issuer or the JWKS URI clears the keys, raises their
     * version and clears the cooldown and token, an issuer's also the discovery
     * document's refresh dates; anything else clears nothing.
     *
     * @param  string  $protocol
     * @param  list<string>  $changed
     * @param  bool  $keys
     * @param  bool  $metadata
     * @return void
     */
    #[DataProvider('provideResets')]
    public function testAnUpdateClearsWhatWasFetchedForTheIssuerOrUrl(string $protocol, array $changed, bool $keys, bool $metadata): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol, 'jwks_version' => 3]);

        $reset = [
            ...($keys ? ['jwks' => null, 'jwks_version' => 4, 'jwks_fetched_at' => null, 'jwks_refetch_at' => null, 'jwks_claim_token' => null] : []),
            ...($metadata ? ['metadata_fetched_at' => null, 'metadata_valid_until' => null, 'metadata_refresh_at' => null] : []),
        ];

        self::assertSame($reset, ProviderKeys::resetFor($connection, $changed));
    }

    /**
     * How each logged record reads.
     *
     * @return list<array{0: string, 1: string, 2: array<array-key, mixed>}>
     */
    private function logged(): array
    {
        return array_map(static fn (array $record): array => [$record['level'], $record['message'], $record['context']], $this->capturedLogRecords());
    }

    /**
     * An OIDC connection pointing at the provider, storing the keys given.
     *
     * @param  ?string  $jwks
     * @param  array<string, mixed>  $attributes
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(?string $jwks, array $attributes = []): Connection
    {
        return $this->makeConnection(['jwks' => $jwks, 'settings' => ['issuer' => self::ISSUER, 'jwks_uri' => self::ISSUER . '/jwks'], ...$attributes]);
    }

    /**
     * The service, from the container.
     *
     * @return \SineMacula\Laravel\Sso\Metadata\ProviderKeys
     */
    private function keys(): ProviderKeys
    {
        return app(ProviderKeys::class);
    }

    /**
     * The keys as a connection stores them.
     *
     * @param  list<\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey>  $keys
     * @return string
     */
    private static function stored(array $keys): string
    {
        $jwks = (string) json_encode(['keys' => array_map(static fn (FakeSigningKey $key): array => $key->jwk(), $keys)]);

        return ProviderKeySet::read($jwks, self::rs256(), 65536, 50)?->toStored() ?? '';
    }

    /**
     * The RS256 allow-list.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     */
    private static function rs256(): AlgorithmAllowList
    {
        return AlgorithmAllowList::of(['RS256']);
    }

    /**
     * A token signed by the key under the `kid`, or none.
     *
     * @param  ?string  $kid
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken
     *
     * @throws \LogicException
     */
    private static function token(?string $kid): CompactToken
    {
        return CompactToken::parse(self::tokenText($kid), 16384) ?? throw new \LogicException('The token was refused.');
    }

    /**
     * The text of a token signed by the key under the `kid`, or none.
     *
     * @param  ?string  $kid
     * @return string
     */
    private static function tokenText(?string $kid): string
    {
        return JwsSigner::sign(array_filter(['alg' => 'RS256', 'kid' => $kid], is_string(...)), ['sub' => 'a'], self::key());
    }

    /**
     * The key's modulus, as its JWK gives it.
     *
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey  $key
     * @return string
     */
    private static function modulusOf(FakeSigningKey $key): string
    {
        $modulus = $key->jwk()['n'] ?? null;

        return is_string($modulus) ? $modulus : self::fail('The key has no modulus.');
    }

    /**
     * The key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa();
    }

    /**
     * The provider's next key, generated once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function next(): FakeSigningKey
    {
        return self::$next ??= FakeSigningKey::rsa('rsa-2');
    }
}
