<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;
use SineMacula\Laravel\Sso\Testing\Oidc\JwsSigner;
use Tests\Concerns\TreatsWarningsAsErrors;

/**
 * Unit tests for an identity provider's JWKS as the package reads and stores it
 * (SSO-7.3): the caps, the strict reading, the keys left out and the refusals;
 * the stored form admitted again for the allow-list; the key chosen by exact
 * `kid`, the missing-`kid` rule, and an unknown `kid` never falling back; and
 * what a replacement adds and removes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProviderKeySet::class)]
#[CoversClass(KeySelection::class)]
#[CoversClass(KeySelectionOutcome::class)]
final class ProviderKeySetTest extends TestCase
{
    use TreatsWarningsAsErrors;

    /** @var array<string, \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey> The keys, generated once. */
    private static array $keys = [];

    /**
     * A JWKS is read with the keys it admits, in order, leaving out those it
     * does not.
     *
     * @return void
     */
    public function testAJwksIsReadWithTheKeysItAdmits(): void
    {
        $jwks = ['keys' => [self::key('k1')->jwk(), ['kty' => 'oct', 'k' => 'c2VjcmV0', 'kid' => 'h1'], self::key('e1')->jwk('ES256'), self::key('k2')->jwk(null, 'enc')]];

        $set = ProviderKeySet::read((string) json_encode($jwks), self::allowed(), 65536, 50);

        self::assertSame(['k1', 'e1'], array_map(static fn (ProviderKey $key): ?string => $key->keyId(), (array) $set?->keys));
    }

    /**
     * A JWKS of exactly the byte cap and the key cap is read; one byte or one
     * key more is refused.
     *
     * @return void
     */
    public function testTheCapsAreHeldAtTheirBoundaries(): void
    {
        $json = (string) json_encode(['keys' => [self::key('k1')->jwk(), self::key('k2')->jwk()]]);

        self::assertNotNull(ProviderKeySet::read($json, self::allowed(), strlen($json), 2));
        self::assertNull(ProviderKeySet::read($json, self::allowed(), strlen($json) - 1, 2));
        self::assertNull(ProviderKeySet::read($json, self::allowed(), strlen($json), 1));
    }

    /**
     * Rows of `[json]`: a JWKS that is refused whole.
     *
     * @return iterable<string, array{0: \Closure(): string}>
     */
    public static function provideRefusedSets(): iterable
    {
        $set     = static fn (array $keys): string => (string) json_encode(['keys' => $keys]);
        $written = static fn (array $jwk, string $member): string => '{"keys":[' . substr((string) json_encode($jwk), 0, -1) . ',"' . $member . '":99999999999999999999}]}';

        yield from [
            'not JSON'                    => [static fn (): string => '{"keys":'],
            'a list'                      => [static fn (): string => '[]'],
            'no keys'                     => [static fn (): string => '{}'],
            'keys an object'              => [static fn (): string => '{"keys":{"a":{}}}'],
            'keys a string'               => [static fn (): string => '{"keys":"k1"}'],
            'an entry not an object'      => [static fn (): string => $set([self::key('k1')->jwk(), 'k2'])],
            'an entry a list'             => [static fn (): string => $set([self::key('k1')->jwk(), [1, 2]])],
            'an entry an empty list'      => [static fn (): string => $set([self::key('k1')->jwk(), []])],
            'keys an object of a list'    => [static fn (): string => '{"keys":{"0":' . json_encode(self::key('k1')->jwk()) . '}}'],
            'keys an empty object'        => [static fn (): string => '{"keys":{}}'],
            'key_ops an object of a list' => [static fn (): string => $set([self::key('k1')->jwk(extra: ['key_ops' => (object) ['verify']])])],
            'a kid too large a number'    => [static fn (): string => $written(self::key('k1')->withKid(null)->jwk(), 'kid')],
            'a use too large a number'    => [static fn (): string => $written(self::key('k1')->jwk(use: null), 'use')],
            'a repeated member'           => [static fn (): string => '{"keys":[],"keys":[' . json_encode(self::key('k1')->jwk()) . ']}'],
            'a repeated member in a key'  => [static fn (): string => '{"keys":[' . substr((string) json_encode(self::key('k1')->jwk()), 0, -1) . ',"kid":"k9"}]}'],
            'two usable keys under a kid' => [static fn (): string => $set([self::key('k1')->jwk(), self::key('k2')->withKid('k1')->jwk()])],
            'no usable key'               => [static fn (): string => $set([['kty' => 'oct', 'k' => 'c2VjcmV0']])],
            'empty keys'                  => [static fn (): string => $set([])],
        ];
    }

    /**
     * A JWKS that is not one object with a list of key objects, repeats a
     * member, holds two usable keys under one `kid` or none at all, is refused.
     *
     * @param  \Closure(): string  $json
     * @return void
     */
    #[DataProvider('provideRefusedSets')]
    public function testARefusedJwksIsNotRead(\Closure $json): void
    {
        self::assertNull(ProviderKeySet::read($json(), self::allowed(), 65536, 50));
    }

    /**
     * An entry that is an empty object is a key the package does not admit, so
     * it is left out rather than refusing the JWKS.
     *
     * @return void
     */
    public function testAnEmptyObjectIsLeftOut(): void
    {
        $json = '{"keys":[{},' . json_encode(self::key('k1')->jwk()) . ']}';

        self::assertSame(['k1'], array_map(static fn (ProviderKey $key): ?string => $key->keyId(), (array) ProviderKeySet::read($json, self::allowed(), 65536, 50)?->keys));
    }

    /**
     * Two keys under one `kid`, one usable and one not, do not refuse the JWKS.
     *
     * @return void
     */
    public function testAKidSharedWithAnUnusableKeyIsRead(): void
    {
        $json = (string) json_encode(['keys' => [self::key('k1')->jwk(), self::key('k2')->withKid('k1')->jwk(null, 'enc')]]);

        self::assertCount(1, (array) ProviderKeySet::read($json, self::allowed(), 65536, 50)?->keys);
    }

    /**
     * The stored form round-trips, and is admitted again for the allow-list as
     * it is read; what cannot be read stores no key.
     *
     * @return void
     */
    public function testTheStoredFormIsAdmittedAgain(): void
    {
        $json = (string) json_encode(['keys' => [self::key('k1')->jwk('RS256'), self::key('e1')->jwk('ES256')]]);
        $set  = ProviderKeySet::read($json, self::allowed(), 65536, 50);

        $stored = (string) $set?->toStored();

        $rsa = self::key('k1')->jwk('RS256');
        $ec  = self::key('e1')->jwk('ES256');

        self::assertSame((string) json_encode([
            ['kty' => 'RSA', 'kid' => 'k1', 'use' => 'sig', 'alg' => 'RS256', 'n' => $rsa['n'], 'e' => $rsa['e']],
            ['kty' => 'EC', 'kid' => 'e1', 'use' => 'sig', 'alg' => 'ES256', 'crv' => 'P-256', 'x' => $ec['x'], 'y' => $ec['y']],
        ], JSON_UNESCAPED_SLASHES), $stored);
        self::assertCount(2, ProviderKeySet::fromStored($stored, self::allowed())->keys);
        self::assertCount(1, ProviderKeySet::fromStored($stored, AlgorithmAllowList::of(['ES256']))->keys);
        self::assertSame([], ProviderKeySet::fromStored(null, self::allowed())->keys);
        self::assertSame([], ProviderKeySet::fromStored('not json', self::allowed())->keys);
        self::assertSame([], ProviderKeySet::fromStored('{"a":1}', self::allowed())->keys);
        self::assertSame([], ProviderKeySet::fromStored('[{"kty":"oct","k":"c2VjcmV0"}]', self::allowed())->keys);
        self::assertSame([], ProviderKeySet::fromStored('[1]', self::allowed())->keys);
    }

    /**
     * Rows of `[header, outcome, kid]`: the key chosen for a token's header
     * from `k1` (RSA, no `alg`), `k2` (RSA, RS256) and `e1` (P-256, ES256).
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome, 2: ?string}>
     */
    public static function provideSelections(): iterable
    {
        yield from [
            'kid k1, RS256'                 => [['alg' => 'RS256', 'kid' => 'k1'], KeySelectionOutcome::FOUND, 'k1'],
            'kid k1, PS256'                 => [['alg' => 'PS256', 'kid' => 'k1'], KeySelectionOutcome::FOUND, 'k1'],
            'kid k2, RS256'                 => [['alg' => 'RS256', 'kid' => 'k2'], KeySelectionOutcome::FOUND, 'k2'],
            'kid e1, ES256'                 => [['alg' => 'ES256', 'kid' => 'e1'], KeySelectionOutcome::FOUND, 'e1'],
            'kid k2, PS256 refused by alg'  => [['alg' => 'PS256', 'kid' => 'k2'], KeySelectionOutcome::REFUSED, null],
            'kid k1, ES256 refused by kty'  => [['alg' => 'ES256', 'kid' => 'k1'], KeySelectionOutcome::REFUSED, null],
            'kid e1, RS256 refused'         => [['alg' => 'RS256', 'kid' => 'e1'], KeySelectionOutcome::REFUSED, null],
            'alg off the allow-list'        => [['alg' => 'RS384', 'kid' => 'k1'], KeySelectionOutcome::REFUSED, null],
            'alg HS256'                     => [['alg' => 'HS256', 'kid' => 'k1'], KeySelectionOutcome::REFUSED, null],
            'alg none'                      => [['alg' => 'none', 'kid' => 'k1'], KeySelectionOutcome::REFUSED, null],
            'alg off the list, kid unknown' => [['alg' => 'HS256', 'kid' => 'nope'], KeySelectionOutcome::REFUSED, null],
            'kid unknown'                   => [['alg' => 'RS256', 'kid' => 'k3'], KeySelectionOutcome::UNKNOWN, null],
            'kid in another case'           => [['alg' => 'RS256', 'kid' => 'K1'], KeySelectionOutcome::UNKNOWN, null],
            'kid with a space'              => [['alg' => 'RS256', 'kid' => 'k1 '], KeySelectionOutcome::UNKNOWN, null],
            'kid a path'                    => [['alg' => 'RS256', 'kid' => '../k1'], KeySelectionOutcome::UNKNOWN, null],
            'kid "0"'                       => [['alg' => 'RS256', 'kid' => '0'], KeySelectionOutcome::UNKNOWN, null],
            'no kid, two RS256 keys'        => [['alg' => 'RS256'], KeySelectionOutcome::REFUSED, null],
            'no kid, one PS256 key'         => [['alg' => 'PS256'], KeySelectionOutcome::FOUND, 'k1'],
            'no kid, one ES256 key'         => [['alg' => 'ES256'], KeySelectionOutcome::FOUND, 'e1'],
        ];
    }

    /**
     * The key is the one whose own `kid` is exactly the header's, or, with no
     * header `kid`, the only key admissible for its algorithm; an unknown `kid`
     * is unknown and never falls back.
     *
     * @param  array<string, mixed>  $header
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome  $outcome
     * @param  ?string  $kid
     * @return void
     */
    #[DataProvider('provideSelections')]
    public function testTheKeyIsChosenByExactKid(array $header, KeySelectionOutcome $outcome, ?string $kid): void
    {
        $allowed   = AlgorithmAllowList::of(['RS256', 'PS256', 'ES256']);
        $set       = self::honest($allowed);
        $selection = $set->select(self::token($header), $allowed);

        self::assertSame([$outcome, $kid], [$selection->outcome, $selection->key?->keyId()]);
        self::assertSame($outcome === KeySelectionOutcome::FOUND, $selection->isFound());
        self::assertSame($outcome === KeySelectionOutcome::UNKNOWN, $selection->isUnknown());
    }

    /**
     * A `kid` of `"0"` never reaches a key without one, and a token with no
     * `kid` reaches a key without one when it is the only admissible key.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAKeyWithoutAKidIsReachedOnlyWithoutOne(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256']);
        $json    = (string) json_encode(['keys' => [self::key('k1')->withKid(null)->jwk()]]);
        $set     = ProviderKeySet::read($json, $allowed, 65536, 50) ?? throw new \LogicException('The JWKS was refused.');

        self::assertSame(KeySelectionOutcome::UNKNOWN, $set->select(self::token(['alg' => 'RS256', 'kid' => '0']), $allowed)->outcome);
        self::assertSame(KeySelectionOutcome::FOUND, $set->select(self::token(['alg' => 'RS256']), $allowed)->outcome);
        self::assertSame(KeySelectionOutcome::UNKNOWN, ProviderKeySet::fromStored('[]', $allowed)->select(self::token(['alg' => 'RS256']), $allowed)->outcome);
    }

    /**
     * A replacement counts the keys it adds and those it removes, a key kept
     * under its `kid` in another form counting as both.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAReplacementCountsWhatItAddsAndRemoves(): void
    {
        $allowed = AlgorithmAllowList::of(['RS256', 'PS256', 'ES256']);
        $set     = static fn (array $keys): ProviderKeySet => ProviderKeySet::read((string) json_encode(['keys' => $keys]), $allowed, 65536, 50) ?? throw new \LogicException;

        $before = $set([self::key('k1')->jwk(), self::key('k2')->jwk('RS256')]);

        self::assertSame(['added' => 0, 'removed' => 0], $set([self::key('k2')->jwk('RS256'), self::key('k1')->jwk()])->changesFrom($before));
        self::assertSame(['added' => 1, 'removed' => 0], $set([self::key('k1')->jwk(), self::key('k2')->jwk('RS256'), self::key('e1')->jwk()])->changesFrom($before));
        self::assertSame(['added' => 0, 'removed' => 1], $set([self::key('k1')->jwk()])->changesFrom($before));
        self::assertSame(['added' => 1, 'removed' => 1], $set([self::key('k1')->jwk(), self::key('e1')->withKid('k2')->jwk()])->changesFrom($before));
        self::assertSame(['added' => 1, 'removed' => 1], $set([self::key('k1')->jwk('RS256'), self::key('k2')->jwk('RS256')])->changesFrom($before));
    }

    /**
     * Two keys with no `kid` do not share one, so a JWKS of them is read.
     *
     * @return void
     */
    public function testTwoKeysWithNoKidAreRead(): void
    {
        $jwks = ['keys' => [self::key('k1')->withKid(null)->jwk(), self::key('k2')->withKid(null)->jwk()]];

        $set = ProviderKeySet::read((string) json_encode($jwks), self::allowed(), 65536, 50);

        self::assertSame([null, null], array_map(static fn (ProviderKey $key): ?string => $key->keyId(), (array) $set?->keys));
    }

    /**
     * The honest set: `k1` (RSA, no `alg`), `k2` (RSA, RS256), `e1` (P-256,
     * ES256).
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList  $allowed
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKeySet
     *
     * @throws \LogicException
     */
    private static function honest(AlgorithmAllowList $allowed): ProviderKeySet
    {
        $json = (string) json_encode(['keys' => [self::key('k1')->jwk(), self::key('k2')->jwk('RS256'), self::key('e1')->jwk('ES256')]]);

        return ProviderKeySet::read($json, $allowed, 65536, 50) ?? throw new \LogicException('The honest JWKS was refused.');
    }

    /**
     * A token of the header, read.
     *
     * @param  array<string, mixed>  $header
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\CompactToken
     *
     * @throws \LogicException
     */
    private static function token(array $header): CompactToken
    {
        return CompactToken::parse(JwsSigner::hmac($header, ['sub' => 'a'], 'x'), 16384) ?? throw new \LogicException('The token was refused.');
    }

    /**
     * Every algorithm the tests use.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList
     */
    private static function allowed(): AlgorithmAllowList
    {
        return AlgorithmAllowList::of(['RS256', 'PS256', 'ES256']);
    }

    /**
     * A key by its name, generated once: `k1` and `k2` RSA, `e1` P-256.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey
     */
    private static function key(string $name): FakeSigningKey
    {
        return self::$keys[$name] ??= str_starts_with($name, 'e') ? FakeSigningKey::ec($name) : FakeSigningKey::rsa($name);
    }
}
