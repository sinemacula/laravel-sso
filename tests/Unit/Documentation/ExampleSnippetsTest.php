<?php

declare(strict_types = 1);

namespace Tests\Unit\Documentation;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Integration\Examples\Snippets;

/**
 * Holds every documented snippet identical to the example region it names.
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
     * Rows of `[source path, region name, code]`, keyed by the marker's place.
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
     * The snippet is a fenced block identical to the region it names.
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
     * Every example region is shown by a snippet, and none is opened twice.
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
     * Every PHP block in the guides and README is a marked snippet.
     *
     * @return void
     */
    public function testEveryPhpBlockIsASnippet(): void
    {
        $unmarked = [];

        foreach (self::documents() as $document => $markdown) {
            foreach (Snippets::phpBlocks($markdown) as $place => $marked) {

                if ($marked) {
                    continue;
                }

                $unmarked[] = "{$document}#{$place}";
            }
        }

        self::assertSame([], $unmarked, 'These PHP blocks are taken from no executed example.');
    }

    /**
     * The reader parses markers, blocks and regions as the docs write them.
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
     * Every example PHP source, keyed by its path from the package root.
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
