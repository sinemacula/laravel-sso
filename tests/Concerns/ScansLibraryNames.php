<?php

declare(strict_types = 1);

namespace Tests\Concerns;

/**
 * Reads the names a PHP source writes in a library's namespaces, so an
 * architecture test can hold the package to the adapter it chose for that
 * library: each name as written (qualified, fully qualified, a member of a
 * group `use` joined to its prefix, or quoted, a doubled backslash read as
 * one), with whether a `use` imports it.
 *
 * The source is tokenised, not parsed: a name built at run time is not seen.
 * The scan is a backstop for the rules, not a proof of them; the adversarial
 * fixtures prove the behaviour.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait ScansLibraryNames
{
    /** @var ?array<string, string> Every PHP file the package ships, by its path relative to the package, read once. */
    private static ?array $shippedSources = null;

    /**
     * Every library name in the source that the pattern matches, in order, and
     * whether a `use` imports it.
     *
     * @param  string  $source
     * @param  string  $pattern
     * @return list<array{0: string, 1: bool}>
     */
    protected static function scannedNames(string $source, string $pattern): array
    {
        $tokens = array_values(array_filter(token_get_all($source), static fn ($token): bool => !is_array($token) || $token[0] !== T_WHITESPACE));
        $found  = [];
        $state  = ['use' => false, 'group' => null];

        foreach ($tokens as $index => $token) {

            $state = self::stateAfter($state, $token, $tokens[$index + 1] ?? null);
            $name  = self::nameOf($token, $state, $tokens[$index - 1] ?? null, $tokens[$index + 1] ?? null);

            if ($name === null || preg_match($pattern, $name) !== 1) {
                continue;
            }

            $found[] = [$name, $state['use']];
        }

        return $found;
    }

    /**
     * Every PHP file the package ships, by its path relative to the package.
     *
     * @return array<string, string>
     */
    protected static function shippedSources(): array
    {
        if (self::$shippedSources !== null) {
            return self::$shippedSources;
        }

        $root  = dirname(__DIR__, 2) . '/';
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . 'src', \FilesystemIterator::SKIP_DOTS));

        self::$shippedSources = [];

        foreach ($files as $file) {

            if (!$file instanceof \SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }

            self::$shippedSources[substr($file->getPathname(), strlen($root))] = (string) file_get_contents($file->getPathname());
        }

        ksort(self::$shippedSources);

        return self::$shippedSources;
    }

    /**
     * Where the scan is once the token is read: inside a `use` statement until
     * its `;`, and inside a group `use`'s braces, with its prefix, until `}`.
     *
     * @param  array{use: bool, group: ?string}  $state
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return array{use: bool, group: ?string}
     */
    private static function stateAfter(array $state, array|string $token, array|string|null $next): array
    {
        return match (true) {
            self::opensUse($token, $next)                    => ['use' => true, 'group' => null],
            $token === ';'                                   => ['use' => false, 'group' => null],
            $token === '}'                                   => [...$state, 'group' => null],
            $state['use'] && self::opensGroup($token, $next) => [...$state, 'group' => ltrim($token[1], '\\')],
            default                                          => $state,
        };
    }

    /**
     * Whether the token opens a `use` statement: an import or a trait's, never
     * a closure's `use (`.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return bool
     */
    private static function opensUse(array|string $token, array|string|null $next): bool
    {
        return is_array($token) && $token[0] === T_USE && $next !== '(';
    }

    /**
     * Whether the token is a group `use`'s prefix: a name followed by `\` and
     * an opening brace.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return bool
     *
     * @phpstan-assert-if-true array{0: int, 1: string, 2: int} $token
     */
    private static function opensGroup(array|string $token, array|string|null $next): bool
    {
        return is_array($token) && is_array($next) && $next[0] === T_NS_SEPARATOR && in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_STRING], true);
    }

    /**
     * The name the token writes, or `null` when it writes none: a qualified
     * name as written, unless it is a group `use`'s prefix; a member of a group
     * joined to its prefix, never its alias; and a quoted string unquoted.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @param  array{use: bool, group: ?string}  $state
     * @param  array{0: int, 1: string, 2: int}|string|null  $previous
     * @param  array{0: int, 1: string, 2: int}|string|null  $next
     * @return ?string
     */
    private static function nameOf(array|string $token, array $state, array|string|null $previous, array|string|null $next): ?string
    {
        if (!is_array($token) || self::opensGroup($token, $next)) {
            return null;
        }

        $member = $state['group'] !== null && !(is_array($previous) && $previous[0] === T_AS);

        return match (true) {
            $member && in_array($token[0], [T_NAME_QUALIFIED, T_STRING], true)    => $state['group'] . '\\' . $token[1],
            in_array($token[0], [T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED], true) => $token[1],
            $token[0] === T_CONSTANT_ENCAPSED_STRING                              => str_replace('\\\\', '\\', substr($token[1], 1, -1)),
            default                                                               => null,
        };
    }
}
