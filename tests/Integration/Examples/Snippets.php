<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

/**
 * Reads the documentation's snippets and the example regions they are taken
 * from, so a test can hold each snippet to its source.
 *
 * A region is the lines between `// @snippet-start <name>` and
 * `// @snippet-end <name>`, dedented; a snippet is the fenced block after a
 * `<!-- snippet: <path>#<name> -->` line.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class Snippets
{
    /** @var string A marker naming the region a snippet is taken from. */
    private const string MARKER = '/^<!-- snippet: (?<path>[^#\s]+)#(?<name>[a-z0-9-]+) -->$/';

    /** @var string A line that opens or closes a region. */
    private const string BOUNDARY = '/^\s*\/\/ @snippet-(?<edge>start|end) (?<name>[a-z0-9-]+)\s*$/';

    /**
     * The package's root directory.
     *
     * @return string
     */
    public static function root(): string
    {
        return dirname(__DIR__, 3);
    }

    /**
     * Every snippet the Markdown shows, in order: the line its marker is on,
     * the source path and region it names, and the code its fenced block holds,
     * or `null` when no fenced block follows the marker.
     *
     * @param  string  $markdown
     * @return list<array{line: int, path: string, name: string, code: ?string}>
     */
    public static function shown(string $markdown): array
    {
        $lines    = explode("\n", str_replace("\r\n", "\n", $markdown));
        $snippets = [];

        foreach ($lines as $index => $line) {

            if (preg_match(self::MARKER, trim($line), $marker) !== 1) {
                continue;
            }

            $snippets[] = ['line' => $index + 1, 'path' => $marker['path'], 'name' => $marker['name'], 'code' => self::fenced($lines, $index + 1)];
        }

        return $snippets;
    }

    /**
     * Whether each PHP block of the Markdown follows a snippet marker, by its
     * place among the PHP blocks, from 1.
     *
     * @param  string  $markdown
     * @return array<int, bool>
     */
    public static function phpBlocks(string $markdown): array
    {
        $blocks   = [];
        $open     = false;
        $previous = '';

        foreach (explode("\n", str_replace("\r\n", "\n", $markdown)) as $line) {

            $text = trim($line);

            if (str_starts_with($text, '```')) {
                $blocks += !$open && $text === '```php' ? [count($blocks) + 1 => preg_match(self::MARKER, $previous) === 1] : [];
                $open = !$open;
            }

            $previous = $text === '' ? $previous : $text;
        }

        return $blocks;
    }

    /**
     * The region of the source with the name, its shared indentation removed,
     * or `null` when the source has no such region, or opens it and never
     * closes it.
     *
     * @param  string  $source
     * @param  string  $name
     * @return ?string
     */
    public static function region(string $source, string $name): ?string
    {
        $inside = null;

        foreach (explode("\n", str_replace("\r\n", "\n", $source)) as $line) {

            $boundary = preg_match(self::BOUNDARY, $line, $edge) === 1 && $edge['name'] === $name ? $edge['edge'] : null;

            if ($boundary === 'end' && $inside !== null) {
                return self::dedented($inside);
            }

            $inside = match (true) {
                $boundary === 'start' => [],
                $inside !== null      => [...$inside, $line],
                default               => null,
            };
        }

        return null;
    }

    /**
     * The name of every region the source opens, in order.
     *
     * @param  string  $source
     * @return list<string>
     */
    public static function regions(string $source): array
    {
        preg_match_all('/^\s*\/\/ @snippet-start ([a-z0-9-]+)\s*$/m', $source, $matches);

        return $matches[1];
    }

    /**
     * The code of the fenced block that starts at the line, after any blank
     * lines, or `null` when none does or it never closes.
     *
     * @param  list<string>  $lines
     * @param  int  $from
     * @return ?string
     */
    private static function fenced(array $lines, int $from): ?string
    {
        $index = $from;

        while (isset($lines[$index]) && trim($lines[$index]) === '') {
            $index++;
        }

        if (!str_starts_with($lines[$index] ?? '', '```')) {
            return null;
        }

        $close = array_search('```', array_slice($lines, $index + 1, null, true), true);

        return is_int($close) ? implode("\n", array_slice($lines, $index + 1, $close - $index - 1)) : null;
    }

    /**
     * The lines with the indentation they share removed, blank lines emptied,
     * joined.
     *
     * @param  list<string>  $lines
     * @return string
     */
    private static function dedented(array $lines): string
    {
        $filled  = array_filter($lines, static fn (string $line): bool => trim($line) !== '');
        $indents = array_map(static fn (string $line): int => strlen($line) - strlen(ltrim($line, ' ')), $filled);
        $shared  = $indents === [] ? 0 : min($indents);

        return implode("\n", array_map(static fn (string $line): string => trim($line) === '' ? '' : substr($line, $shared), $lines));
    }
}
