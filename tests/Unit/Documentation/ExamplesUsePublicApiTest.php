<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ScansLibraryNames;
use Tests\Integration\Examples\Snippets;

/**
 * The public-API gate of the executable examples (SSO-12.4): an application
 * tests its flows with what the package publishes, so every example, and the
 * harness they run on, names only the package's public classes (none marked
 * `@internal`, and no model, since reading a table is not the public API, but
 * for the two `@api` models whose class alone is public, admitted by name with
 * their reason in `ADMITTED_MODELS`), none of the package's own test traits or
 * fixtures (only the examples' own classes, and the base test case in the
 * harness alone, for the database the suite runs on), names none of the
 * package's tables, and builds no verified result by hand; the application's
 * own tables are its to use. And every public testing helper is in the testing
 * guide, so the guide covers the whole helper surface.
 *
 * Names are read as `ScansLibraryNames` reads them, from the source's tokens.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ExamplesUsePublicApiTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string A name in the package's namespace or the tests'. */
    private const string NAMES = '/^\\\?(?:SineMacula\\\Laravel\\\Sso|Tests)\\\/';

    /** @var string What names one of the package's tables (by its default name, or by its setting) or builds a verified result. */
    private const string FORBIDDEN = '/[\'"]sso_(?:single_use_keys|rate_limits|connections|keys|domains|enforcement|links'
        . '|authorization_requests|handoff_codes|identity_guards)[\'"]|config\(\s*[\'"]sso\.[a-z_.]*table[\'"]|new\s+\\\?(?:\w+\\\)*VerifiedResult\b/';

    /** @var string The package's namespace. */
    private const string PACKAGE = 'SineMacula\Laravel\Sso\\';

    /** @var string The examples' own namespace, which they may name. */
    private const string EXAMPLES = 'Tests\Integration\Examples';

    /** @var array<string, string> The package's models an example may name, by class, with the reason. */
    private const array ADMITTED_MODELS = [
        'SineMacula\Laravel\Sso\Models\RateLimit'    => 'docs/guides/rate-limits.md schedules `model:prune` naming its class, the one part of it that is public',
        'SineMacula\Laravel\Sso\Models\SingleUseKey' => 'docs/guides/single-use-store.md schedules `model:prune` naming its class, the one part of it that is public',
    ];

    /**
     * Rows of `[path]`: every PHP source of the examples and their harness.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideExamples(): iterable
    {
        $root  = Snippets::root();
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/tests/Integration/Examples', \FilesystemIterator::SKIP_DOTS));
        $paths = [];

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $paths[] = substr($file->getPathname(), strlen($root) + 1);
        }

        sort($paths);

        foreach ($paths as $path) {
            yield $path => [$path];
        }
    }

    /**
     * The source names only the package's public API, and only the tests'
     * classes an example may.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideExamples')]
    public function testNamesOnlyThePublicApi(string $path): void
    {
        $source = (string) file_get_contents(Snippets::root() . '/' . $path);

        self::assertSame([], self::violations($source, basename($path)), "{$path} names what an application could not.");
    }

    /**
     * The source names none of the package's tables and builds no verified
     * result; the application's own tables are its to use.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideExamples')]
    public function testReadsNoTableOfThePackageAndBuildsNoResult(string $path): void
    {
        $source = (string) file_get_contents(Snippets::root() . '/' . $path);

        self::assertSame(0, preg_match(self::FORBIDDEN, $source, $found), "{$path} names a table of the package or builds a verified result: " . ($found[0] ?? ''));
    }

    /**
     * Every public class of the testing helpers is named in the testing guide.
     *
     * @return void
     */
    public function testEveryPublicHelperIsInTheGuide(): void
    {
        $root    = Snippets::root();
        $guide   = (string) file_get_contents($root . '/docs/guides/testing.md');
        $missing = [];
        $helpers = [...(glob($root . '/src/Testing/*.php') ?: []), ...(glob($root . '/src/Testing/*/*.php') ?: [])];

        foreach ($helpers as $file) {

            $class = self::PACKAGE . str_replace('/', '\\', substr($file, strlen($root . '/src/'), -4));
            $short = basename($file, '.php');
            $named = str_contains($guide, "`{$short}`") || str_contains($guide, "\\{$short}`");

            if ($named || !self::isPublic($class)) {
                continue;
            }

            $missing[] = $class;
        }

        self::assertNotSame([], $helpers);
        self::assertSame([], $missing, 'These public testing helpers are not in docs/guides/testing.md.');
    }

    /**
     * The gate catches an internal class, a model, a class that does not exist,
     * the package's own test traits and its base test case outside the harness,
     * a table of the package's and a hand-built result, and passes a public
     * class, the two admitted models, the examples' own, and the application's
     * own table.
     *
     * @return void
     */
    public function testTheGateCatchesWhatItShould(): void
    {
        $source = <<<'PHP'
            <?php
            namespace Tests\Integration\Examples;
            use SineMacula\Laravel\Sso\Completion\CompletionPipeline;
            use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
            use SineMacula\Laravel\Sso\Models\Link;
            use SineMacula\Laravel\Sso\Models\RateLimit;
            use SineMacula\Laravel\Sso\Models\SingleUseKey;
            use SineMacula\Laravel\Sso\Nothing\Here;
            use Tests\Concerns\FlowRoutes;
            use Tests\Integration\Examples\Application\ExampleSessions;
            use Tests\TestCase;
            PHP;

        self::assertSame([
            'SineMacula\Laravel\Sso\Completion\CompletionPipeline',
            'SineMacula\Laravel\Sso\Models\Link',
            'SineMacula\Laravel\Sso\Nothing\Here',
            'Tests\Concerns\FlowRoutes',
            'Tests\TestCase',
        ], self::violations($source, 'AnExampleTest.php'));

        self::assertSame([
            'SineMacula\Laravel\Sso\Completion\CompletionPipeline',
            'SineMacula\Laravel\Sso\Models\Link',
            'SineMacula\Laravel\Sso\Nothing\Here',
            'Tests\Concerns\FlowRoutes',
        ], self::violations($source, 'ExampleTestCase.php'));

        $forbidden = [
            'DB::table(\'sso_links\')',
            'Schema::hasTable("sso_handoff_codes")',
            'DB::table(config(\'sso.links.table\'))',
            'new VerifiedResult(',
            'new \SineMacula\Laravel\Sso\Results\VerifiedResult(',
        ];

        foreach ($forbidden as $read) {
            self::assertSame(1, preg_match(self::FORBIDDEN, $read), $read);
        }

        foreach (['DB::table(\'connection_tenants\')', 'config()->set(\'sso.features.saml2\', true);', '\'sso_url\' => $url', '\'_sso-verification.example.com\''] as $allowed) {
            self::assertSame(0, preg_match(self::FORBIDDEN, $allowed), $allowed);
        }

        foreach (glob(Snippets::root() . '/database/migrations/*.php') ?: [] as $migration) {
            self::assertSame(1, preg_match('/create_(sso_\w+)_table\.php$/', $migration, $table), $migration);
            self::assertSame(1, preg_match(self::FORBIDDEN, "'{$table[1]}'"), "The gate does not know the table {$table[1]}.");
        }
    }

    /**
     * The names in the source an example may not use, in order: a tests' class
     * outside the examples (the base test case allowed in the harness alone),
     * and a package class that is not public.
     *
     * @param  string  $source
     * @param  string  $file
     * @return list<string>
     */
    private static function violations(string $source, string $file): array
    {
        $names   = array_values(array_unique(array_map(static fn (array $found): string => ltrim($found[0], '\\'), self::scannedNames($source, self::NAMES))));
        $refused = static fn (string $name): bool => str_starts_with($name, 'Tests\\') ? !self::isOwn($name, $file) : !self::isPublic($name);

        return array_values(array_filter($names, $refused));
    }

    /**
     * Whether a tests' name is one an example may use: the examples' own, or
     * the base test case in the harness.
     *
     * @param  string  $name
     * @param  string  $file
     * @return bool
     */
    private static function isOwn(string $name, string $file): bool
    {
        return str_starts_with($name, self::EXAMPLES) || ($name === 'Tests\TestCase' && $file === 'ExampleTestCase.php');
    }

    /**
     * Whether the package's class, interface or enum exists, is not a model,
     * and is not marked `@internal`.
     *
     * @param  string  $name
     * @return bool
     */
    private static function isPublic(string $name): bool
    {
        $exists = class_exists($name) || interface_exists($name) || enum_exists($name);

        if (!$exists || (str_starts_with($name, self::PACKAGE . 'Models\\') && !array_key_exists($name, self::ADMITTED_MODELS))) {
            return false;
        }

        /** @var class-string $class */
        $class   = $name;
        $comment = (new \ReflectionClass($class))->getDocComment();

        return !is_string($comment) || !str_contains($comment, '@internal');
    }
}
