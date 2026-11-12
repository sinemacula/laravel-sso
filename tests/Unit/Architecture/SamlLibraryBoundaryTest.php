<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ScansLibraryNames;

/**
 * Architecture tests for the SAML library conditions in
 * `docs/design/saml-library.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class SamlLibraryBoundaryTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string The adapter's directory, relative to the package. */
    private const string ADAPTER = 'src/Protocols/Saml2/Library/';

    /** @var string The one class that calls a signed element's `verify()`. */
    private const string VERIFIER = 'src/Protocols/Saml2/Library/PinnedVerifier.php';

    /** @var string The one class that sets the library's container. */
    private const string CONTAINER = 'src/Protocols/Saml2/Library/LibraryContainer.php';

    /** @var string A name in the library's namespaces. */
    private const string LIBRARY = '/\\\?SimpleSAML\\\/';

    /** @var list<string> Namespace prefixes of the library the package never names. */
    private const array FORBIDDEN = [
        'SimpleSAML\SAML2\Response\Processor',
        'SimpleSAML\SAML2\Signature\Validator',
        'SimpleSAML\SAML2\Signature\\',
        'SimpleSAML\SAML2\Assertion\\',
        'SimpleSAML\SAML2\Response\\',
        'SimpleSAML\SAML2\Binding',
        'SimpleSAML\SAML2\HTTPRedirect',
        'SimpleSAML\SAML2\HTTPPost',
    ];

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
     * A file outside the adapter names neither library.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSourcesOutsideTheAdapter')]
    public function testOnlyTheAdapterNamesTheLibrary(string $path): void
    {
        self::assertSame([], self::libraryNames(self::shippedSources()[$path]), "{$path} names the SAML library outside the adapter.");
    }

    /**
     * The adapter names the library, so the rule above holds over something.
     *
     * @return void
     */
    public function testTheAdapterNamesTheLibrary(): void
    {
        self::assertNotSame([], self::libraryNames(self::shippedSources()[self::VERIFIER]));
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
     * No file names a forbidden part of the library.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingNamesTheHighLevelProcessorsValidatorsOrBindings(string $path): void
    {
        self::assertSame([], self::forbidden(self::shippedSources()[$path]), "{$path} names a part of the SAML library the package never uses.");
    }

    /**
     * Only the pinned verifier calls `verify()`, and never without an argument.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testVerifyIsCalledOnlyByThePinnedVerifierAndAlwaysWithAVerifier(string $path): void
    {
        $calls = self::verifyCalls(self::shippedSources()[$path]);

        self::assertNotContains(0, $calls, "{$path} calls verify() without a verifier.");

        if ($path === self::VERIFIER || !str_starts_with($path, self::ADAPTER)) {
            return;
        }

        self::assertSame([], $calls, "{$path} calls verify() outside the pinned verifier.");
    }

    /**
     * Only the adapter's container sets the library's container.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testOnlyTheAdapterContainerSetsTheLibraryContainer(string $path): void
    {
        $sets = str_contains(self::shippedSources()[$path], 'setContainer(') && str_contains(self::shippedSources()[$path], 'ContainerSingleton');

        self::assertSame($path === self::CONTAINER, $sets, "{$path} and the library's container.");
    }

    /**
     * The pinned verifier calls `verify()` once, with an argument, so the rule
     * above holds over something.
     *
     * @return void
     */
    public function testThePinnedVerifierCallsVerifyWithAVerifier(): void
    {
        $source = self::shippedSources()[self::VERIFIER];

        self::assertSame([1], self::verifyCalls($source));
        self::assertStringContainsString('->verify((new SignatureAlgorithmFactory)->getAlgorithm($algorithm, $key))', $source);
        self::assertStringContainsString('$key      = (new X509Certificate(PEM::fromString($certificate)))->getPublicKey();', $source);
    }

    /**
     * The scans find library names however written, forbidden parts and each
     * `verify()` call's argument count.
     *
     * @return void
     */
    public function testTheScansFindWhatTheyLookFor(): void
    {
        $source = <<<'PHP'
            <?php

            use SimpleSAML\SAML2\Response\Processor;
            use SimpleSAML\SAML2\{Binding, Signature\Validator as Chain};
            use \SimpleSAML\SAML2\{XML\saml\Assertion};
            use SimpleSAML\SAML2\Assertion;
            use SimpleSAML\SAML2\XML\samlp\Response;

            $a->verify();
            $b->verify($verifier);
            $c->verify($one, $two);
            new \SimpleSAML\SAML2\Signature\Validator();
            $d->verifyNothing();
            $e = 'SimpleSAML\SAML2\HTTPPost';
            $f = "SimpleSAML\\SAML2\\HTTPRedirect";
            $g = static function () use ($a): string { return SimpleSAML\SAML2\Response::class; };
            PHP;

        self::assertSame([
            'SimpleSAML\SAML2\Response\Processor',
            'SimpleSAML\SAML2\Binding',
            'SimpleSAML\SAML2\Signature\Validator',
            'SimpleSAML\SAML2\XML\saml\Assertion',
            'SimpleSAML\SAML2\Assertion',
            'SimpleSAML\SAML2\XML\samlp\Response',
            '\SimpleSAML\SAML2\Signature\Validator',
            'SimpleSAML\SAML2\HTTPPost',
            'SimpleSAML\SAML2\HTTPRedirect',
            'SimpleSAML\SAML2\Response',
        ], self::libraryNames($source));
        self::assertSame([
            'SimpleSAML\SAML2\Response\Processor',
            'SimpleSAML\SAML2\Binding',
            'SimpleSAML\SAML2\Signature\Validator',
            'SimpleSAML\SAML2\Assertion',
            '\SimpleSAML\SAML2\Signature\Validator',
            'SimpleSAML\SAML2\HTTPPost',
            'SimpleSAML\SAML2\HTTPRedirect',
        ], self::forbidden($source));
        self::assertSame(['SimpleSAML\SAML2'], self::forbidden("<?php\nuse SimpleSAML\\SAML2;\n"));
        self::assertSame([], self::forbidden("<?php\n\$x = SimpleSAML\\SAML2\\Response::class;\n"));
        self::assertSame([0, 1, 2], self::verifyCalls($source));
    }

    /**
     * Every name in the source in the library's namespaces.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function libraryNames(string $source): array
    {
        return array_column(self::scannedNames($source, self::LIBRARY), 0);
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
     * The number of arguments of each `->verify(` call in the source.
     *
     * @param  string  $source
     * @return list<int>
     */
    private static function verifyCalls(string $source): array
    {
        $code   = static fn ($token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true);
        $tokens = array_values(array_filter(token_get_all($source), $code));
        $calls  = [];

        foreach (array_keys($tokens) as $index) {

            if (!self::isVerifyCall($tokens, $index)) {
                continue;
            }

            $calls[] = self::arguments($tokens, $index + 1);
        }

        return $calls;
    }

    /**
     * Whether the token at the index names a `->verify(` method call.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return bool
     */
    private static function isVerifyCall(array $tokens, int $index): bool
    {
        $token    = $tokens[$index];
        $previous = $tokens[$index - 1] ?? null;

        $isName    = is_array($token)    && $token[0] === T_STRING && $token[1] === 'verify';
        $isMethod  = is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR], true);
        $isOpening = ($tokens[$index + 1] ?? null) === '(';

        return $isName && $isMethod && $isOpening;
    }

    /**
     * The number of top-level arguments of the call opening at the index.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $open
     * @return int
     */
    private static function arguments(array $tokens, int $open): int
    {
        if (($tokens[$open + 1] ?? null) === ')') {
            return 0;
        }

        $depth     = 0;
        $arguments = 1;

        for ($index = $open; $index < count($tokens); $index++) {

            $token = $tokens[$index];
            $depth += match ($token) {
                '(', '[', '{' => 1,
                ')', ']', '}' => -1,
                default       => 0,
            };

            if ($depth === 0) {
                break;
            }

            $arguments += $token === ',' && $depth === 1 ? 1 : 0;
        }

        return $arguments;
    }
}
