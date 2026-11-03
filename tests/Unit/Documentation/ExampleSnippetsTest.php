<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Integration\Examples\Snippets;

/**
 * Holds every snippet the documentation shows to the executable example it is
 * taken from (SSO-12.4, SSO-12.5): each `<!-- snippet: <path>#<name> -->` in a
 * guide or the README is followed by a fenced block that is exactly that region
 * of that source, so changing an example without its snippet, or a snippet
 * without its example, fails here. Every region an example opens is shown
 * somewhere, so no example is kept for a snippet nobody reads. Every other PHP
 * block is listed, with its reason, in `UnsourcedSnippets`, so the code no test
 * runs is known and cannot grow unnoticed.
 *
 * The examples themselves run in the Integration suite, against the public API
 * alone (`ExamplesUsePublicApiTest`); this reads files and covers no code.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class ExampleSnippetsTest extends TestCase
{
    /** @var string Where the executable examples are, relative to the package's root. */
    private const string EXAMPLES = 'tests/Integration/Examples';

    /**
     * Rows of `[source path, region name, the snippet's code]`: every snippet
     * the guides and the README show, by the file and line of its marker.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideSnippets(): iterable
    {
        foreach (self::documents() as $document => $markdown) {
            foreach (Snippets::shown($markdown) as $snippet) {
                yield "{$document}:{$snippet['line']}" => [$snippet['path'], $snippet['name'], $snippet['code']];
            }
        }
    }

    /**
     * The snippet is a fenced block, and exactly the region of the source it
     * names.
     *
     * @param  string  $path
     * @param  string  $name
     * @param  ?string  $code
     * @return void
     */
    #[DataProvider('provideSnippets')]
    public function testEachSnippetIsItsRegion(string $path, string $name, ?string $code): void
    {
        $file = Snippets::root() . '/' . $path;

        self::assertFileExists($file, "The snippet names {$path}, which does not exist.");
        self::assertNotNull($code, "The snippet of {$path}#{$name} is not followed by a fenced block.");

        $region = Snippets::region((string) file_get_contents($file), $name);

        self::assertNotNull($region, "{$path} has no region {$name}.");
        self::assertSame($region, $code, "The snippet of {$path}#{$name} differs from its source.");
    }

    /**
     * Every region of every example is shown by a snippet, and no source opens
     * a region twice.
     *
     * @return void
     */
    public function testEveryRegionIsShown(): void
    {
        $shown   = [];
        $regions = [];

        foreach (self::documents() as $markdown) {
            foreach (Snippets::shown($markdown) as $snippet) {
                $shown[] = "{$snippet['path']}#{$snippet['name']}";
            }
        }

        foreach (self::examples() as $path => $source) {

            $names = Snippets::regions($source);

            self::assertSame(array_values(array_unique($names)), $names, "{$path} opens a region twice.");

            foreach ($names as $name) {
                $regions[] = "{$path}#{$name}";
            }
        }

        self::assertNotSame([], $regions);
        self::assertSame([], array_values(array_diff($regions, $shown)), 'These regions are shown by no snippet.');
    }

    /**
     * Every PHP block of a guide or the README is a marked snippet, or is
     * listed in `UnsourcedSnippets` with its reason; and every block listed
     * there is still an unmarked PHP block. A new block that no example runs
     * fails here until it is taken from one, or listed.
     *
     * @return void
     */
    public function testEveryPhpBlockIsASnippetOrListedWithItsReason(): void
    {
        $unmarked = [];

        foreach (self::documents() as $document => $markdown) {
            foreach (Snippets::phpBlocks($markdown) as $place => $marked) {

                if ($marked) {
                    continue;
                }

                $unmarked[$document][$place] = UnsourcedSnippets::FENCES[$document][$place] ?? 'unlisted';
            }
        }

        self::assertSame(UnsourcedSnippets::FENCES, $unmarked);
    }

    /**
     * The reader finds a marker's fenced block after blank lines, and none
     * where no block follows or one never closes; it reads a region with its
     * shared indentation removed and its blank lines emptied, and none where a
     * region is missing or never closes; it lists the regions a source opens;
     * and it tells a marked PHP block, indented or not, from one with no marker
     * right before it.
     *
     * @return void
     */
    public function testTheReaderReadsWhatTheDocumentationWrites(): void
    {
        $markdown = implode("\n", [
            'Text',
            '<!-- snippet: tests/Example.php#first -->',
            '',
            '```php',
            '$a = 1;',
            '',
            '$b = 2;',
            '```',
            '<!-- snippet: tests/Example.php#second -->',
            'Not a fence',
            '<!-- snippet: tests/Example.php#third -->',
            '```php',
            '$never = "closed";',
        ]);

        $source = implode("\n", [
            '<?php',
            '    // @snippet-start first',
            '    $a = 1;',
            '',
            '        $b = 2;',
            '    // @snippet-end first',
            '    // @snippet-start open',
            '    $c = 3;',
        ]);

        self::assertSame([
            ['line' => 2, 'path' => 'tests/Example.php', 'name' => 'first', 'code' => "\$a = 1;\n\n\$b = 2;"],
            ['line' => 9, 'path' => 'tests/Example.php', 'name' => 'second', 'code' => null],
            ['line' => 11, 'path' => 'tests/Example.php', 'name' => 'third', 'code' => null],
        ], Snippets::shown($markdown));

        self::assertSame([1 => true, 2 => true], Snippets::phpBlocks($markdown));
        self::assertSame([1 => false, 2 => true, 3 => false], Snippets::phpBlocks(implode("\n", [
            '```php',
            '$a = 1;',
            '```',
            '<!-- snippet: tests/Example.php#first -->',
            '',
            '   ```php',
            '   $b = 2;',
            '   ```',
            '```text',
            '<!-- snippet: tests/Example.php#second -->',
            '```',
            '```php',
            '$c = 3;',
            '```',
        ])));
        self::assertSame("\$a = 1;\n\n    \$b = 2;", Snippets::region($source, 'first'));
        self::assertNull(Snippets::region($source, 'open'));
        self::assertNull(Snippets::region($source, 'missing'));
        self::assertSame(['first', 'open'], Snippets::regions($source));
    }

    /**
     * The guides and the README, by their path relative to the package's root.
     *
     * @return array<string, string>
     */
    private static function documents(): array
    {
        $root  = Snippets::root();
        $files = [...(glob($root . '/docs/guides/*.md') ?: []), $root . '/README.md'];
        $read  = [];

        foreach ($files as $file) {
            $read[substr($file, strlen($root) + 1)] = (string) file_get_contents($file);
        }

        ksort($read);

        return $read;
    }

    /**
     * Every PHP source of the examples, by its path relative to the package's
     * root.
     *
     * @return array<string, string>
     */
    private static function examples(): array
    {
        $root  = Snippets::root();
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . '/' . self::EXAMPLES, \FilesystemIterator::SKIP_DOTS));
        $read  = [];

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            $read[substr($file->getPathname(), strlen($root) + 1)] = (string) file_get_contents($file->getPathname());
        }

        ksort($read);

        return $read;
    }
}
