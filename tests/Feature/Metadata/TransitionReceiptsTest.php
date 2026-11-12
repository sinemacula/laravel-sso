<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Metadata\TransitionReceipts;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use Tests\Concerns\DumpsValues;
use Tests\Concerns\UsesConnections;
use Tests\Concerns\UsesFlowTables;
use Tests\Fixtures\FixedClock;
use Tests\TestCase;

/**
 * Feature tests for judging a transition receipt at the final locks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(TransitionReceipts::class)]
#[CoversClass(TransitionReceipt::class)]
final class TransitionReceiptsTest extends TestCase
{
    use DumpsValues, UsesConnections, UsesFlowTables;

    /** @var ?\SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey The key the token verified with, made once. */
    private static ?FakeSigningKey $key = null;

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
     * The exact transition is permitted.
     *
     * @return void
     */
    public function testTheExactTransitionIsPermitted(): void
    {
        [$connection, $request, $receipt] = $this->arrange();

        self::assertTrue(TransitionReceipts::permits($receipt, $connection, $request));
    }

    /**
     * Without a receipt nothing is permitted.
     *
     * @return void
     */
    public function testNoReceiptPermitsNothing(): void
    {
        [$connection, $request] = $this->arrange();

        self::assertFalse(TransitionReceipts::permits(null, $connection, $request));
    }

    /**
     * Rows of `[request attributes, connection attributes]` no longer as the
     * receipt named.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: array<string, mixed>}>
     */
    public static function provideChangedRows(): iterable
    {
        yield from [
            'the request voided'                => [['voided_at' => CarbonImmutable::parse('2026-11-01T09:30:00Z')], []],
            'the request finished'              => [['completed_at' => CarbonImmutable::parse('2026-11-01T09:30:00Z')], []],
            'the request not consumed'          => [['consumed_at' => null], []],
            'the request of an older trust'     => [['trust_version' => 3], []],
            'the request adopting the new'      => [['trust_version' => 5], []],
            'the connection at a later trust'   => [[], ['trust_version' => 6]],
            'the connection at the older trust' => [[], ['trust_version' => 4]],
            'the keys written since'            => [[], ['jwks_version' => 8]],
            'the keys of an older version'      => [[], ['jwks_version' => 6]],
            'the key gone from what is stored'  => [[], ['jwks' => '[]']],
            'nothing stored'                    => [[], ['jwks' => null]],
        ];
    }

    /**
     * A request or connection no longer exactly as named refuses, each alone.
     *
     * @param  array<string, mixed>  $requestAttributes
     * @param  array<string, mixed>  $connectionAttributes
     * @return void
     */
    #[DataProvider('provideChangedRows')]
    public function testARowNoLongerAsNamedRefuses(array $requestAttributes, array $connectionAttributes): void
    {
        [$connection, $request, $receipt] = $this->arrange();

        $connection->forceFill($connectionAttributes);
        $request->forceFill($requestAttributes);

        self::assertFalse(TransitionReceipts::permits($receipt, $connection, $request));
    }

    /**
     * A receipt of another request or another connection refuses.
     *
     * @return void
     */
    public function testAReceiptOfAnotherRowRefuses(): void
    {
        [$connection, $request, $receipt] = $this->arrange();

        $otherConnection = new TransitionReceipt('01jbotherconnection0000000', $receipt->requestId, 4, 5, 7, $receipt->keyThumbprint(), $receipt->algorithm);
        $otherRequest    = new TransitionReceipt($receipt->connectionId, '01jbotherrequest0000000000', 4, 5, 7, $receipt->keyThumbprint(), $receipt->algorithm);

        self::assertFalse(TransitionReceipts::permits($otherConnection, $connection, $request));
        self::assertFalse(TransitionReceipts::permits($otherRequest, $connection, $request));
    }

    /**
     * A key no longer admitted for its algorithm under the locked allow-list
     * refuses, as do another key and an unbuildable allow-list.
     *
     * @return void
     */
    public function testTheKeyMustStillBeAdmitted(): void
    {
        [$connection, $request, $receipt] = $this->arrange();

        $another = $receipt->withKey(str_repeat('a', 43), 'RS256');

        self::assertFalse(TransitionReceipts::permits($another, $connection, $request));
        self::assertFalse(TransitionReceipts::permits($receipt->withKey((string) $receipt->keyThumbprint(), 'PS256'), $connection, $request));

        foreach ([['PS256'], ['none']] as $algorithms) {
            $connection->forceFill(['settings' => ['id_token_algorithms' => $algorithms]]);

            self::assertFalse(TransitionReceipts::permits($receipt, $connection, $request));
        }
    }

    /**
     * A receipt that never learned its key refuses.
     *
     * @return void
     */
    public function testAReceiptWithNoKeyRefuses(): void
    {
        [$connection, $request, $receipt] = $this->arrange();

        self::assertFalse(TransitionReceipts::permits(new TransitionReceipt($receipt->connectionId, $receipt->requestId, 4, 5, 7), $connection, $request));
    }

    /**
     * A receipt refuses serialisation and its dump shows only the versions.
     *
     * @return void
     */
    public function testAReceiptIsNeverKeptOrShown(): void
    {
        $receipt = new TransitionReceipt('c1', 'r1', 4, 5, 7, 'the-key-thumbprint', 'RS256');

        foreach (self::dumps($receipt) as $dump) {
            self::assertStringNotContainsString('the-key-thumbprint', $dump);
        }

        self::assertSame(['connection_id' => 'c1', 'request_id' => 'r1', 'from_trust_version' => 4, 'to_trust_version' => 5, 'jwks_version' => 7], $receipt->__debugInfo());

        $this->expectExceptionObject(new \LogicException('A transition receipt cannot be serialised.'));

        serialize($receipt);
    }

    /**
     * Unserialising a receipt is refused.
     *
     * @return void
     */
    public function testAReceiptIsNeverUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A transition receipt cannot be unserialised.'));

        unserialize('O:' . strlen(TransitionReceipt::class) . ':"' . TransitionReceipt::class . '":0:{}');
    }

    /**
     * A connection at trust 5 and JWKS 7, a consumed request at trust 4, and a
     * receipt for that transition.
     *
     * @return array{0: \SineMacula\Laravel\Sso\Models\Connection, 1: \SineMacula\Laravel\Sso\Models\AuthorizationRequest, 2: \SineMacula\Laravel\Sso\Protocols\TransitionReceipt}
     *
     * @throws \LogicException
     */
    private function arrange(): array
    {
        $allowed    = AlgorithmAllowList::of(['RS256']);
        $jwks       = (string) json_encode(['keys' => [self::key()->jwk()]]);
        $connection = $this->makeConnection([
            'protocol'      => 'oidc',
            'trust_version' => 5,
            'jwks_version'  => 7,
            'jwks'          => ProviderKeySet::read($jwks, $allowed, 65536, 50)?->toStored(),
            'settings'      => ['id_token_algorithms' => ['RS256']],
        ]);
        $request = $this->makeAuthorizationRequest($connection, ['trust_version' => 4, 'consumed_at' => app(Clock::class)->now()]);
        $key     = ProviderKey::admit(self::key()->jwk(), $allowed) ?? throw new \LogicException('The key is admitted.');

        return [$connection, $request, new TransitionReceipt($connection->id, $request->id, 4, 5, 7, $key->thumbprint(), 'RS256')];
    }

    /**
     * The key the token verified with, made once.
     *
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(): FakeSigningKey
    {
        return self::$key ??= FakeSigningKey::rsa('rsa-1');
    }
}
