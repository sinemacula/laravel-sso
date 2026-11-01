<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Holds the package's namespaces to the dependency rules its design states:
 * which classes may not name which others. Each rule is data in `RULES`, so a
 * change that moves a class or narrows a dependency adds or tightens a rule
 * there. A rule applies to the classes in its `from` namespaces or classes (`*`
 * for every class of the package) except those in `except`, and forbids them to
 * name anything in its `forbids` namespaces or classes except what `allows`
 * lists; every name is relative to the package.
 *
 * A class names another through an import (`use`, grouped or aliased), a
 * qualified or fully qualified name in its code, or a fully qualified type in a
 * docblock. Names resolve as PHP resolves them, without regard to case, and a
 * qualified name only through a class or namespace import. The source is
 * tokenised, not parsed, so a name built at run time (a class name in a string,
 * say) and an unqualified name of a class in the same namespace are not seen:
 * the test is a backstop for the rules, not a proof of them.
 *
 * One rule names what is outside the package: only `Logging` names the log
 * manager, a logger, the `Log` facade or the `logger()` and `info()` helpers,
 * so every log call the package makes goes through `Logging\SanitizingLogger`.
 *
 * One rule is about the suite rather than the package: the package stands
 * alone, so nothing it ships (its classes, configuration, migrations and
 * translations) names a sibling package's namespace (`SineMacula\Laravel\*`
 * other than `Sso`) or reads a sibling's configuration (`authentication.`,
 * `authorization.`, `mfa.`, `iam.`, `audit-log.`), and `composer.json` requires
 * no sibling. That rule reads the raw text, strings and comments included, so a
 * name a class builds at run time is caught too.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class NamespaceDependenciesTest extends TestCase
{
    /** @var string The namespace every name below is relative to. */
    private const string PACKAGE = 'SineMacula\Laravel\Sso\\';

    /** @var string A fully qualified package name in a docblock. */
    private const string DOCBLOCK_NAME = '/\\\(SineMacula\\\Laravel\\\Sso\\\[A-Za-z0-9_\\\]+)/i';

    /** @var string A sibling package's namespace: `SineMacula\Laravel\` and any member but `Sso`, with any number of backslashes, as code or a string writes it. */
    private const string SIBLING_NAMESPACE = '/SineMacula\\\+Laravel\\\+(?!Sso(?![A-Za-z0-9_]))[A-Za-z_][A-Za-z0-9_]*/i';

    /** @var string A string that reads a sibling package's configuration. */
    private const string SIBLING_CONFIG = '/[\'"](?:authentication|authorization|mfa|iam|audit[_-]log)\.[A-Za-z_]/i';

    /** @var string A sibling package's Composer name. */
    private const string SIBLING_PACKAGE = '#^sinemacula/laravel-(?!sso$)[a-z0-9-]+$#i';

    /** @var list<string> The directories the package ships code, configuration, migrations and translations in. */
    private const array SHIPPED = ['src', 'config', 'database', 'lang'];

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The rules, by what each holds. */
    private const array RULES = [
        'contracts name no implementation' => [
            'from'    => ['Contracts'],
            'except'  => [],
            'forbids' => ['Config', 'Console', 'Database', 'Exceptions', 'Models'],
            'allows'  => [],
        ],
        'configuration and storage name no model, event or console' => [
            'from'    => ['Config', 'Database'],
            'except'  => [],
            'forbids' => ['Console', 'Events', 'Models'],
            'allows'  => [],
        ],
        'models name nothing but storage and the contracts' => [
            'from'    => ['Models'],
            'except'  => [],
            'forbids' => ['Config', 'Console', 'Events', 'Exceptions'],
            'allows'  => [],
        ],
        'events name no model, configuration or console' => [
            'from'    => ['Events'],
            'except'  => [],
            'forbids' => ['Config', 'Console', 'Models'],
            'allows'  => [],
        ],
        'protocol drivers read a connection through its contract' => [
            'from'    => ['Protocols'],
            'except'  => [],
            'forbids' => ['Models', 'Administration', 'Console'],
            'allows'  => [],
        ],
        'only the composition root names the console' => [
            'from'    => ['*'],
            'except'  => ['SsoServiceProvider', 'Console'],
            'forbids' => ['Console'],
            'allows'  => [],
        ],
        'nothing names the composition root' => [
            'from'    => ['*'],
            'except'  => [],
            'forbids' => ['SsoServiceProvider'],
            'allows'  => [],
        ],
        'only the testing helpers name the testing helpers' => [
            'from'    => ['*'],
            'except'  => ['Testing'],
            'forbids' => ['Testing'],
            'allows'  => [],
        ],
    ];

    /** @var list<string> What writes to the application's logs directly, by its lower-case name: the log manager, its loggers, the `Log` facade (imported or by its global alias) and the `logger()` and `info()` helpers. Only `Logging` names them, so every log call the package makes goes through `Logging\SanitizingLogger`. */
    private const array LOG_WRITERS = [
        'illuminate\log\logmanager',
        'illuminate\log\logger',
        'illuminate\support\facades\log',
        'log',
        'logger',
        'info',
    ];

    /** @var ?array<string, list<string>> Every class of the package and the package names it names, read once. */
    private static ?array $names = null;

    /** @var ?array<string, string> Every class of the package and its source, read once. */
    private static ?array $sources = null;

    /**
     * Rows of `[from, except, forbids, allows]`: each rule.
     *
     * @return iterable<string, array{0: list<string>, 1: list<string>, 2: list<string>, 3: list<string>}>
     */
    public static function provideRules(): iterable
    {
        foreach (self::RULES as $rule => $scope) {
            yield $rule => [$scope['from'], $scope['except'], $scope['forbids'], $scope['allows']];
        }
    }

    /**
     * No class a rule applies to names anything it forbids.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testNoClassNamesWhatItsRuleForbids(array $from, array $except, array $forbids, array $allows): void
    {
        self::assertSame([], self::violations(self::names(), $from, $except, $forbids, $allows));
    }

    /**
     * Every namespace or class a rule names has a class in it, so a rule left
     * behind by a move fails rather than holding over nothing.
     *
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return void
     */
    #[DataProvider('provideRules')]
    public function testEveryNameARuleGivesExists(array $from, array $except, array $forbids, array $allows): void
    {
        $classes = array_keys(self::names());

        foreach ([...$from, ...$except, ...$forbids, ...$allows] as $named) {
            self::assertNotSame([], array_filter($classes, static fn (string $class): bool => self::isWithin($class, [$named])), "No class of the package is in {$named}.");
        }
    }

    /**
     * Nothing the package ships names a sibling package's namespace or reads a
     * sibling's configuration: the package stands alone, and `laravel-iam`
     * adapts it.
     *
     * @return void
     */
    public function testNothingThePackageShipsNamesASibling(): void
    {
        $found = [];

        foreach (self::shippedFiles() as $path => $contents) {
            array_push($found, ...array_map(static fn (string $reference): string => "{$path} names {$reference}", self::siblingReferencesIn($contents)));
        }

        self::assertSame([], $found);
    }

    /**
     * `composer.json` requires no sibling package, at run time or in
     * development.
     *
     * @return void
     */
    public function testComposerRequiresNoSibling(): void
    {
        /** @var array{require?: array<string, string>, require-dev?: array<string, string>} $composer */
        $composer = json_decode((string) file_get_contents(dirname(__DIR__, 3) . '/composer.json'), true, flags: JSON_THROW_ON_ERROR);

        $packages = array_keys([...$composer['require'] ?? [], ...$composer['require-dev'] ?? []]);

        self::assertSame([], array_values(array_filter($packages, static fn (string $package): bool => preg_match(self::SIBLING_PACKAGE, $package) === 1)));
    }

    /**
     * Only `Logging` writes to the application's logs directly: every other
     * class logs through `Logging\SanitizingLogger`, so nothing it logs skips
     * sanitisation and redaction.
     *
     * @return void
     */
    public function testOnlyLoggingNamesTheLogManagerOrTheLogFacade(): void
    {
        $found = [];

        foreach (self::sources() as $class => $source) {

            if (self::isWithin($class, ['Logging'])) {
                continue;
            }

            array_push($found, ...array_map(static fn (string $name): string => "{$class} names {$name}", self::logWritersIn($source)));
        }

        self::assertSame([], $found);
        self::assertNotSame([], self::logWritersIn(self::sources()['Logging\SanitizingLogger']));
    }

    /**
     * The log scan finds the log manager, a logger and the `Log` facade however
     * a class names them (imported, aliased, fully qualified, by the global
     * alias) and a call to the `logger()` or `info()` helper, and nothing for a
     * PSR-3 logger, a method or a function of the same name, or a name that
     * only starts like one.
     *
     * @return void
     */
    public function testTheLogScanFindsEveryWayOfWritingToTheLogs(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Example;

            use Illuminate\Log\LogManager;
            use Illuminate\Support\Facades\Log as Logs;
            use Psr\Log\LoggerInterface;

            final class Example
            {
                public function run(LoggerInterface $logger): void
                {
                    new \Illuminate\Log\Logger($logger);
                    \Log::info('a');
                    logger('b');
                    \info('c');
                    $logger->info('d');
                    self::info('e');
                    Logs::channel('f');
                    $this->logger();
                    new \Illuminate\Log\LogManagerFactory;
                }

                private function logger(): void {}

                private static function info(string $message): void {}
            }
            PHP;

        self::assertSame([
            'Illuminate\Log\LogManager',
            'Illuminate\Support\Facades\Log',
            'Illuminate\Log\Logger',
            'Log',
            'info',
            'logger',
        ], self::logWritersIn($source));
    }

    /**
     * The sibling scan finds a sibling's namespace however it is written (in an
     * import, fully qualified, in a docblock, in a string with doubled
     * backslashes, in any case) and a read of a sibling's configuration through
     * any helper, and nothing for the package's own namespace, a name that only
     * starts like a sibling's, or a sibling mentioned by its Composer name.
     *
     * @return void
     */
    public function testTheSiblingScanFindsEveryWayOfNamingASibling(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Example;

            use SineMacula\Laravel\Authentication\Contracts\Identity;
            use SineMacula\Laravel\Sso\Contracts\Clock;
            use SineMacula\Laravel\SsoExtras\Thing;

            /**
             * Bridges laravel-authentication and laravel-mfa.
             *
             * @see \SineMacula\Laravel\Mfa\Factors\Factor
             */
            final class Example
            {
                public function run(): void
                {
                    new \sinemacula\laravel\iam\Adapter;
                    $class = 'SineMacula\\Laravel\\AuditLog\\Recorder';
                    config('authentication.jwt.keys');
                    Config::get("mfa.factors");
                    $config->get('iam.adapters');
                    config('sso.storage.connection');
                    config('authenticationish.key');
                }
            }
            PHP;

        self::assertSame([
            'SineMacula\Laravel\Authentication',
            'SineMacula\Laravel\SsoExtras',
            'SineMacula\Laravel\Mfa',
            'sinemacula\laravel\iam',
            'SineMacula\\\Laravel\\\AuditLog',
            '\'authentication.j',
            '"mfa.f',
            '\'iam.a',
        ], self::siblingReferencesIn($source));

        self::assertSame(1, preg_match(self::SIBLING_PACKAGE, 'sinemacula/laravel-authentication'));
        self::assertSame(0, preg_match(self::SIBLING_PACKAGE, 'sinemacula/laravel-sso'));
        self::assertSame(0, preg_match(self::SIBLING_PACKAGE, 'sinemacula/coding-standards-laravel'));
    }

    /**
     * The scanner finds a package name however a class names it: imported
     * alone, aliased, grouped, as a function or a constant (alone or within a
     * group), through an alias or relative to its namespace, fully qualified in
     * code or in a docblock; and nothing for an unqualified name, a closure's
     * `use`, or a name outside the package.
     *
     * @return void
     */
    public function testTheScannerFindsEveryWayOfNamingAClass(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Sessions;

            use Illuminate\Support\Str;
            use SineMacula\Laravel\Sso\Jwt\TokenLifetimes;
            use SineMacula\Laravel\Sso\Guards as Guarding;
            use SineMacula\Laravel\Sso\Events\{AuthenticationFailed, Enums\FailureReason as Reason};
            use function SineMacula\Laravel\Sso\Support\helper;
            use SineMacula\Laravel\Sso\{function Jwt\issue, const Guards\FLAG};

            /**
             * @see \SineMacula\Laravel\Sso\Http\ClientContext
             */
            final class Example
            {
                use Concerns\ManagesDevices;

                /** @var \SineMacula\Laravel\Sso\Models\Device */
                private $device;

                public function run(): void
                {
                    $value = 1;

                    $callback = static function () use ($value): int {
                        return $value;
                    };

                    new Guarding\JwtGuard;
                    new \SineMacula\Laravel\Sso\Database\AfterCommit($callback);
                    new namespace\SessionWriter;
                    new SignInResult;
                    Str::random();
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Database\AfterCommit',
            'Events\AuthenticationFailed',
            'Events\Enums\FailureReason',
            'Guards',
            'Guards\FLAG',
            'Guards\JwtGuard',
            'Http\ClientContext',
            'Jwt\TokenLifetimes',
            'Jwt\issue',
            'Models\Device',
            'Sessions\Concerns\ManagesDevices',
            'Sessions\SessionWriter',
            'Support\helper',
        ], $names);
    }

    /**
     * The scanner reads the imports of a bracketed namespace as imports, gives
     * each namespace its own aliases, reads a closure's `use` at the top of a
     * namespace as code, and resolves names in the global namespace from its
     * root.
     *
     * @return void
     */
    public function testTheScannerReadsEachBracketedNamespaceOnItsOwn(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Models {

                use SineMacula\Laravel\Sso\Jwt\TokenLifetimes;
                use SineMacula\Laravel\Sso\Guards as Guarding;

                $resolve = static function () use ($container): void {
                    new \SineMacula\Laravel\Sso\Sessions\SessionService;
                };

                final class Example
                {
                    use Concerns\HasDevices;
                }
            }

            namespace {

                new Guarding\JwtGuard;
                new SineMacula\Laravel\Sso\Database\AfterCommit;
                new namespace\SineMacula\Laravel\Sso\Config\IntegerSetting;
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Config\IntegerSetting',
            'Database\AfterCommit',
            'Guards',
            'Jwt\TokenLifetimes',
            'Models\Concerns\HasDevices',
            'Sessions\SessionService',
        ], $names);
    }

    /**
     * A qualified name resolves through the class or namespace import its first
     * segment names, whatever its case, and not through a function's or a
     * constant's import of the same name, alone or within a group; a rule
     * catches a forbidden name whatever its case, fully qualified in code or in
     * a docblock.
     *
     * @return void
     */
    public function testTheScannerResolvesAQualifiedNameAsPhpDoes(): void
    {
        $source = <<<'PHP'
            <?php

            namespace SineMacula\Laravel\Sso\Models;

            use SineMacula\Laravel\Sso as Auth;
            use SineMacula\Laravel\Sso\Guards as Guarding;
            use SineMacula\Laravel\Sso\Jwt as Tokens;
            use function Other\Auth;
            use CONST Other\Guarding;
            use Other\{FUNCTION tokenize as Tokens, const Auth};

            /**
             * @see \sinemacula\laravel\sso\sessions\SessionService
             */
            final class Example
            {
                public function run(): void
                {
                    new Auth\Jwt\TokenLifetimes;
                    new auth\Sessions\DeviceProof;
                    new GUARDING\JwtGuard;
                    new tokens\JwtKeyring;
                    new \sinemacula\laravel\sso\jwt\MachineTokens;
                }
            }
            PHP;

        $names = self::namesIn($source);

        sort($names);

        self::assertSame([
            'Guards',
            'Guards\JwtGuard',
            'Jwt',
            'Jwt\JwtKeyring',
            'Jwt\TokenLifetimes',
            'Sessions\DeviceProof',
            'jwt\MachineTokens',
            'sessions\SessionService',
        ], $names);

        self::assertSame([
            'Models\Example names Guards',
            'Models\Example names Guards\JwtGuard',
            'Models\Example names Jwt',
            'Models\Example names Jwt\JwtKeyring',
            'Models\Example names Jwt\TokenLifetimes',
            'Models\Example names Sessions\DeviceProof',
            'Models\Example names jwt\MachineTokens',
            'Models\Example names sessions\SessionService',
        ], self::violations(['Models\Example' => $names], ['models'], [], ['JWT', 'Sessions', 'Guards'], []));
    }

    /**
     * Every file the package ships, by its path relative to the package, with
     * its contents.
     *
     * @return array<string, string>
     */
    private static function shippedFiles(): array
    {
        $root  = dirname(__DIR__, 3) . '/';
        $files = [];

        foreach (self::SHIPPED as $directory) {

            if (!is_dir($root . $directory)) {
                continue;
            }

            foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root . $directory, \FilesystemIterator::SKIP_DOTS)) as $file) {

                assert($file instanceof \SplFileInfo);

                $files[substr($file->getPathname(), strlen($root))] = (string) file_get_contents($file->getPathname());
            }
        }

        ksort($files);

        return $files;
    }

    /**
     * The references to a sibling package the text holds, in order: each
     * sibling namespace, then each read of a sibling's configuration.
     *
     * @param  string  $text
     * @return list<string>
     */
    private static function siblingReferencesIn(string $text): array
    {
        preg_match_all(self::SIBLING_NAMESPACE, $text, $namespaces);
        preg_match_all(self::SIBLING_CONFIG, $text, $config);

        return [...$namespaces[0], ...$config[0]];
    }

    /**
     * What each class a rule applies to names that the rule forbids.
     *
     * @param  array<string, list<string>>  $classes
     * @param  list<string>  $from
     * @param  list<string>  $except
     * @param  list<string>  $forbids
     * @param  list<string>  $allows
     * @return list<string>
     */
    private static function violations(array $classes, array $from, array $except, array $forbids, array $allows): array
    {
        $violations = [];

        foreach ($classes as $class => $names) {

            if (!self::isWithin($class, $from) || self::isWithin($class, $except)) {
                continue;
            }

            foreach ($names as $name) {

                if (!self::isWithin($name, $forbids) || self::isWithin($name, $allows)) {
                    continue;
                }

                $violations[] = "{$class} names {$name}";
            }
        }

        return $violations;
    }

    /**
     * Every class of the package and the package names it names, relative to
     * the package, read once.
     *
     * @return array<string, list<string>>
     */
    private static function names(): array
    {
        return self::$names ??= array_map(self::namesIn(...), self::sources());
    }

    /**
     * Every class of the package and its source, by its name relative to the
     * package, read once.
     *
     * @return array<string, string>
     */
    private static function sources(): array
    {
        if (self::$sources !== null) {
            return self::$sources;
        }

        $source  = dirname(__DIR__, 3) . '/src/';
        $files   = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($source, \FilesystemIterator::SKIP_DOTS));
        $sources = [];

        foreach ($files as $file) {

            assert($file instanceof \SplFileInfo);

            if ($file->getExtension() !== 'php') {
                continue;
            }

            $class = str_replace('/', '\\', substr($file->getPathname(), strlen($source), -4));

            $sources[$class] = (string) file_get_contents($file->getPathname());
        }

        ksort($sources);

        return self::$sources = $sources;
    }

    /**
     * The distinct package names the source names, relative to the package.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function namesIn(string $source): array
    {
        $package = array_filter(self::qualifiedNamesIn($source), static fn (string $name): bool => strncasecmp($name, self::PACKAGE, strlen(self::PACKAGE)) === 0);

        return array_values(array_unique(array_map(static fn (string $name): string => substr($name, strlen(self::PACKAGE)), $package)));
    }

    /**
     * Every distinct fully qualified name the source names, in or outside the
     * package, in the order it first names each.
     *
     * An import is read as one statement, so its names are not read again as
     * names in code; each namespace's body, whether it ends at the next
     * `namespace` or at its closing brace, has its own aliases. The names of a
     * trait's or a closure's `use` are read as names in code.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function qualifiedNamesIn(string $source): array
    {
        $tokens    = self::tokens($source);
        $depths    = self::depths($tokens);
        $namespace = '';
        $body      = 0;
        $aliases   = [];
        $names     = [];

        for ($index = 0, $count = count($tokens); $index < $count; $index++) {

            [$id, $text] = is_array($tokens[$index]) ? $tokens[$index] : [null, $tokens[$index]];

            if ($id === T_NAMESPACE) {
                [$namespace, $body, $index] = self::declared($tokens, $depths, $index);

                $aliases = [];
            } elseif ($id === T_USE && self::isImport($tokens, $depths, $index, $body)) {
                [$statement, $index] = self::statement($tokens, $index + 1);

                array_push($names, ...self::imports($statement, $aliases));
            } elseif ($id === T_DOC_COMMENT) {
                array_push($names, ...self::documented($text));
            } elseif ($id !== null) {
                $names[] = self::qualified($id, $text, $namespace, $aliases);
            }
        }

        return array_values(array_unique(array_filter($names, static fn (?string $name): bool => $name !== null)));
    }

    /**
     * The names of what writes to the application's logs directly that the
     * source names, in the order it first names each: through an import or a
     * qualified name, or as a call of an unqualified function.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function logWritersIn(string $source): array
    {
        $tokens = self::tokens($source);
        $names  = self::qualifiedNamesIn($source);

        foreach ($tokens as $index => $token) {

            if (!is_array($token) || $token[0] !== T_STRING || ($tokens[$index + 1] ?? null) !== '(' || self::isMember($tokens[$index - 1] ?? null)) {
                continue;
            }

            $names[] = $token[1];
        }

        $writers = array_filter($names, static fn (string $name): bool => in_array(strtolower($name), self::LOG_WRITERS, true));

        return array_values(array_unique($writers));
    }

    /**
     * Whether the token before a name makes it a member or a declaration rather
     * than a call of a function: `->`, `?->`, `::`, `function` or `new`.
     *
     * @param  array{0: int, 1: string, 2: int}|string|null  $previous
     * @return bool
     */
    private static function isMember(array|string|null $previous): bool
    {
        return is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true);
    }

    /**
     * The namespace declared at the index, the depth of the braces its imports
     * sit in, and the index of its last token before its body.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @return array{0: string, 1: int, 2: int}
     */
    private static function declared(array $tokens, array $depths, int $index): array
    {
        $namespace = is_array($tokens[$index + 1]) ? self::text($tokens[++$index]) : '';
        $body      = ($tokens[$index + 1] ?? null) === '{' ? $depths[$index] + 1 : $depths[$index];

        return [$namespace, $body, $index];
    }

    /**
     * Whether the `use` at the index is an import: one directly in the
     * namespace's body, not a trait's in a class or a closure's after its
     * parameters.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  list<int>  $depths
     * @param  int  $index
     * @param  int  $body
     * @return bool
     */
    private static function isImport(array $tokens, array $depths, int $index, int $body): bool
    {
        return $depths[$index] === $body && $tokens[$index - 1] !== ')';
    }

    /**
     * The source's tokens, without whitespace and plain comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function tokens(string $source): array
    {
        $meaningful = static fn (array|string $token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT], true);

        return array_values(array_filter(token_get_all($source), $meaningful));
    }

    /**
     * How many braces are open before each token.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @return list<int>
     */
    private static function depths(array $tokens): array
    {
        $depths = [];
        $depth  = 0;

        foreach ($tokens as $token) {

            $depths[] = $depth;

            $depth += match (true) {
                $token === '{', is_array($token) && in_array($token[0], [T_CURLY_OPEN, T_DOLLAR_OPEN_CURLY_BRACES], true) => 1,
                $token === '}'                                                                                            => -1,
                default                                                                                                   => 0,
            };
        }

        return $depths;
    }

    /**
     * The import statement that starts at the index, as text without its
     * whitespace, and the index of its `;`.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return array{0: string, 1: int}
     */
    private static function statement(array $tokens, int $index): array
    {
        $statement = '';

        for (; ($tokens[$index] ?? ';') !== ';'; $index++) {
            $statement .= self::text($tokens[$index]);
        }

        return [$statement, $index];
    }

    /**
     * The text of the token, with a space around `as` and after `function` or
     * `const`, the words an import statement may hold.
     *
     * @param  array{0: int, 1: string, 2: int}|string  $token
     * @return string
     */
    private static function text(array|string $token): string
    {
        if (!is_array($token)) {
            return $token;
        }

        return match ($token[0]) {
            T_AS                => ' as ',
            T_FUNCTION, T_CONST => $token[1] . ' ',
            default             => $token[1],
        };
    }

    /**
     * The names an import statement imports, recording the alias each class or
     * namespace import gives by its lower case. A qualified name resolves only
     * through those, without regard to case: a function's or a constant's
     * import of the same name is kept apart from them.
     *
     * @param  string  $statement
     * @param  array<string, string>  $aliases
     * @return list<string>
     */
    private static function imports(string $statement, array &$aliases): array
    {
        [$kind, $statement] = self::kind($statement, '');

        $prefix = '';

        if (preg_match('/^(.*)\\\\\{(.*)\}$/', $statement, $group) === 1) {
            [, $prefix, $statement] = $group;

            $prefix .= '\\';
        }

        $names = [];

        foreach (explode(',', $statement) as $import) {

            [$member, $import] = self::kind($import, $kind);

            $parts = explode(' as ', $import);
            $name  = ltrim($prefix . $parts[0], '\\');
            $alias = $parts[1] ?? substr((string) strrchr('\\' . $name, '\\'), 1);

            if ($member === '') {
                $aliases[strtolower($alias)] = $name;
            }

            $names[] = $name;
        }

        return $names;
    }

    /**
     * What the import imports, `function`, `const` or `''` for a class or a
     * namespace, and the import without the word that gives it: a whole
     * statement's, or one member's of a group, which imports what its statement
     * does unless it gives its own.
     *
     * @param  string  $import
     * @param  string  $kind
     * @return array{0: string, 1: string}
     */
    private static function kind(string $import, string $kind): array
    {
        if (preg_match('/^(function|const) (.*)$/i', $import, $match) === 1) {
            return [strtolower($match[1]), $match[2]];
        }

        return [$kind, $import];
    }

    /**
     * The fully qualified name a name token stands for: a qualified name
     * through the alias its first segment names, whatever its case, or else
     * relative to the namespace; `null` for any other token.
     *
     * @param  int  $id
     * @param  string  $text
     * @param  string  $namespace
     * @param  array<string, string>  $aliases
     * @return ?string
     */
    private static function qualified(int $id, string $text, string $namespace, array $aliases): ?string
    {
        if ($id === T_NAME_FULLY_QUALIFIED) {
            return substr($text, 1);
        }

        if ($id === T_NAME_RELATIVE) {
            return ltrim($namespace . substr($text, strlen('namespace')), '\\');
        }

        if ($id !== T_NAME_QUALIFIED) {
            return null;
        }

        [$first, $rest] = explode('\\', $text, 2);

        $alias = strtolower($first);

        return isset($aliases[$alias]) ? $aliases[$alias] . '\\' . $rest : ltrim($namespace . '\\' . $text, '\\');
    }

    /**
     * The fully qualified package names a docblock gives.
     *
     * @param  string  $docblock
     * @return list<string>
     */
    private static function documented(string $docblock): array
    {
        preg_match_all(self::DOCBLOCK_NAME, $docblock, $matches);

        return array_map(static fn (string $name): string => rtrim($name, '\\'), $matches[1]);
    }

    /**
     * Whether the name is one of the namespaces or classes, or inside one of
     * them, without regard to case; `*` stands for the whole package.
     *
     * @param  string  $name
     * @param  list<string>  $scopes
     * @return bool
     */
    private static function isWithin(string $name, array $scopes): bool
    {
        $name = strtolower($name);

        foreach (array_map(strtolower(...), $scopes) as $scope) {
            if ($scope === '*' || $name === $scope || str_starts_with($name, $scope . '\\')) {
                return true;
            }
        }

        return false;
    }
}
