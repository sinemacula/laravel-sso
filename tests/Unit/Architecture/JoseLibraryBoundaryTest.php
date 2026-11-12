<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ScansLibraryNames;

/**
 * Architecture tests for the JOSE library conditions in
 * `docs/design/jose-library.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class JoseLibraryBoundaryTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string The adapter's directory, relative to the package. */
    private const string ADAPTER = 'src/Protocols/Oidc/Jose/';

    /** @var string The one class that calls the library. */
    private const string LIBRARY_CALLER = 'src/Protocols/Oidc/Jose/JoseAdapter.php';

    /** @var string A name in the library's namespace, never inside another one. */
    private const string LIBRARY = '/^\\\?Jose\\\/';

    /** @var list<string> Namespace prefixes of the library the package never names. */
    private const array FORBIDDEN = [
        'Jose\Component\Core\JWKSet',
        'Jose\Component\Signature\Algorithm\None',
        'Jose\Component\Signature\Algorithm\HS256',
        'Jose\Component\Signature\Algorithm\HS384',
        'Jose\Component\Signature\Algorithm\HS512',
        'Jose\Component\Signature\Algorithm\HMAC',
        'Jose\Component\Signature\Algorithm\MacAlgorithm',
        'Jose\Component\Signature\Algorithm\EdDSA',
        'Jose\Component\Signature\JWSLoader',
        'Jose\Component\Signature\JWSVerifierFactory',
        'Jose\Component\Signature\Serializer\JSON',
        'Jose\Component\Signature\Serializer\JWSSerializerManager',
        'Jose\Component\Core\AlgorithmManagerFactory',
        'Jose\Component\Checker\\',
        'Jose\Component\Encryption\\',
        'Jose\Component\NestedToken\\',
        'Jose\Component\KeyManagement\\',
        'Jose\Component\Console\\',
    ];

    /** @var list<string> The library methods the package never calls, by name. */
    private const array FORBIDDEN_METHODS = ['verifyWithKeySet'];

    /**
     * Rows of `[path]`: every PHP file the package ships outside the adapter.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSourcesOutsideTheAdapter(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {

            if (str_starts_with($path, self::ADAPTER)) {
                continue;
            }

            yield $path => [$path];
        }
    }

    /**
     * A file outside the adapter names nothing of the library.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSourcesOutsideTheAdapter')]
    public function testOnlyTheAdapterNamesTheLibrary(string $path): void
    {
        self::assertSame([], array_column(self::scannedNames(self::shippedSources()[$path], self::LIBRARY), 0), "{$path} names the JOSE library outside its adapter.");
    }

    /**
     * Rows of `[path]`: every PHP file of the adapter.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideAdapterSources(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {

            if (!str_starts_with($path, self::ADAPTER)) {
                continue;
            }

            yield $path => [$path];
        }
    }

    /**
     * Inside the adapter, only `JoseAdapter` names the library.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideAdapterSources')]
    public function testOnlyTheAdapterClassCallsTheLibrary(string $path): void
    {
        $names = array_column(self::scannedNames(self::shippedSources()[$path], self::LIBRARY), 0);

        self::assertSame($path === self::LIBRARY_CALLER, $names !== [], "{$path} and the JOSE library.");
    }

    /**
     * Rows of `[path]`: every PHP file the package ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSources(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {
            yield $path => [$path];
        }
    }

    /**
     * No file names a forbidden part of the library or calls a forbidden
     * method.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingNamesTheKeySetNoneHmacOrTheLibrarysChecks(string $path): void
    {
        $source = self::shippedSources()[$path];

        self::assertSame([], self::forbidden($source), "{$path} names a part of the JOSE library the package never uses.");
        self::assertSame([], self::forbiddenCalls($source), "{$path} calls a JOSE library method the package never uses.");
    }

    /**
     * The adapter registers exactly the nine asymmetric algorithms, so the
     * rules above hold over something.
     *
     * @return void
     */
    public function testTheAdapterRegistersOnlyAsymmetricAlgorithms(): void
    {
        $source     = self::shippedSources()[self::LIBRARY_CALLER];
        $algorithms = array_values(array_filter(
            array_column(self::scannedNames($source, self::LIBRARY), 0),
            static fn (string $name): bool => str_starts_with($name, 'Jose\Component\Signature\Algorithm\\'),
        ));

        self::assertSame([
            'Jose\Component\Signature\Algorithm\ES256',
            'Jose\Component\Signature\Algorithm\ES384',
            'Jose\Component\Signature\Algorithm\ES512',
            'Jose\Component\Signature\Algorithm\PS256',
            'Jose\Component\Signature\Algorithm\PS384',
            'Jose\Component\Signature\Algorithm\PS512',
            'Jose\Component\Signature\Algorithm\RS256',
            'Jose\Component\Signature\Algorithm\RS384',
            'Jose\Component\Signature\Algorithm\RS512',
            'Jose\Component\Signature\Algorithm\SignatureAlgorithm',
        ], $algorithms);
        self::assertStringContainsString('->verifyWithKey($jws, new JWK($key->toArray()), 0)', $source);
        self::assertStringContainsString('new JWSVerifier(self::manager($allowed->names))', $source);
    }

    /**
     * The scans find library names however written, never the package's own
     * `Jose` namespace, forbidden parts and forbidden calls.
     *
     * @return void
     */
    public function testTheScansFindWhatTheyLookFor(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Protocols\Oidc\Jose;

            use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\StrictJson;
            use Jose\Component\Core\JWKSet;
            use Jose\Component\Signature\Algorithm\{RS256, None as Nothing};
            use Jose\Component\Checker;
            use Jose\Component;

            $a = new \Jose\Component\Signature\Algorithm\HS256();
            $b = 'Jose\Component\Encryption\JWEBuilder';
            $c->verifyWithKeySet($jws, $set, 0);
            $d->verifyWithKey($jws, $key, 0);
            PHP;

        self::assertSame([
            'Jose\Component\Core\JWKSet',
            'Jose\Component\Signature\Algorithm\RS256',
            'Jose\Component\Signature\Algorithm\None',
            'Jose\Component\Checker',
            'Jose\Component',
            '\Jose\Component\Signature\Algorithm\HS256',
            'Jose\Component\Encryption\JWEBuilder',
        ], array_column(self::scannedNames($source, self::LIBRARY), 0));
        self::assertSame([
            'Jose\Component\Core\JWKSet',
            'Jose\Component\Signature\Algorithm\None',
            'Jose\Component\Checker',
            'Jose\Component',
            '\Jose\Component\Signature\Algorithm\HS256',
            'Jose\Component\Encryption\JWEBuilder',
        ], self::forbidden($source));
        self::assertSame(['verifyWithKeySet'], self::forbiddenCalls($source));
    }

    /**
     * Every library name that is a forbidden part or a namespace holding one.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function forbidden(string $source): array
    {
        $found = array_filter(self::scannedNames($source, self::LIBRARY), static fn (array $scanned): bool => self::isForbidden(...$scanned));

        return array_column($found, 0);
    }

    /**
     * Whether the name is a forbidden part or an imported namespace holding
     * one, through which the part could be named relatively.
     *
     * @param  string  $name
     * @param  bool  $imported
     * @return bool
     */
    private static function isForbidden(string $name, bool $imported): bool
    {
        $name = ltrim($name, '\\');

        foreach (self::FORBIDDEN as $prefix) {

            $names   = str_starts_with($name, $prefix);
            $holding = $imported && str_starts_with($prefix, $name . '\\');

            if ($names || $holding) {
                return true;
            }
        }

        return false;
    }

    /**
     * Every forbidden method the source names as an identifier.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function forbiddenCalls(string $source): array
    {
        $identifiers = array_map(
            static fn (array $token): string => $token[1],
            array_filter(token_get_all($source), static fn ($token): bool => is_array($token) && $token[0] === T_STRING),
        );

        return array_values(array_intersect($identifiers, self::FORBIDDEN_METHODS));
    }
}
