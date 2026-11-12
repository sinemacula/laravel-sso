<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Concerns\ScansLibraryNames;
use Tests\Integration\Examples\Snippets;

/**
 * Holds the examples to the public API and the testing guide to every helper.
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

    /** @var string What names a package table, by default name or setting, or builds a result. */
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
     * The source names only public package classes and the examples' own.
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
     * The source reads no package table and builds no verified result.
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
     * The gate flags internal classes, models, fixtures, tables and results.
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
     * The names in the source an example may not use, in order.
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
     * Whether an example may use the name: its own, or the harness's base case.
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
     * Whether the package type exists, is not a model and is not `@internal`.
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
