<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Architecture tests holding the package's namespaces to the rules in `RULES`.
 * Names in the same namespace or built at run time are not seen.
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

    /** @var string A sibling package's namespace, however many backslashes are written. */
    private const string SIBLING_NAMESPACE = '/SineMacula\\\+Laravel\\\+(?!Sso(?![A-Za-z0-9_]))[A-Za-z_][A-Za-z0-9_]*/i';

    /** @var string A string that reads a sibling package's configuration. */
    private const string SIBLING_CONFIG = '/[\'"](?:authentication|authorization|mfa|iam|audit[_-]log)\.[A-Za-z_]/i';

    /** @var string A sibling package named in prose, or one of its requirements cited by id. */
    private const string SIBLING_NAME = '/laravel-(?:authentication|authorization|mfa|iam|audit-log)(?![A-Za-z0-9_-])|\b(?:AUTH|AUTHZ|MFA|IAM|AUDIT)-[0-9]/';

    /** @var string A sibling package's Composer name. */
    private const string SIBLING_PACKAGE = '#^sinemacula/laravel-(?!sso$)[a-z0-9-]+$#i';

    /** @var list<string> The directories the package ships code, configuration, migrations and translations in. */
    private const array SHIPPED = ['src', 'config', 'database', 'lang'];

    /** @var array<string, array{from: non-empty-list<string>, except: list<string>, forbids: non-empty-list<string>, allows: list<string>}> The rules, by what each holds; `*` is the whole package. */
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
        'the client context names nothing else of the package' => [
            'from'    => ['Http'],
            'except'  => [],
            'forbids' => ['*'],
            'allows'  => ['Http'],
        ],
    ];

    /** @var list<string> The classes the application gives the request being served. */
    private const array REQUEST_READERS = ['Http\ClientContext', 'Protocols\CompletionRequest'];

    /** @var string A read of the request being served through the container. */
    private const string CONTAINER_REQUEST = '/->\s*(?:make|bound|get|has|resolved)\s*\(\s*[\'"]request[\'"]/i';

    /** @var list<string> What writes to the application's logs directly, by lower-case name. */
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
     * Every namespace or class a rule names still has a class in it.
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
     * Nothing the package ships, comments included, names or configures a
     * sibling package.
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
     * `composer.json` requires no sibling package, even in development.
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
     * Only `Logging` writes to the application's logs directly, so nothing
     * skips sanitisation and redaction.
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
     * No core service reads the request being served; only the client context
     * and the completion request are given it.
     *
     * @return void
     */
    public function testOnlyTheRequestHelpersReadTheRequest(): void
    {
        $found = [];

        foreach (self::sources() as $class => $source) {

            if (preg_match(self::CONTAINER_REQUEST, $source) === 1) {
                $found[] = "{$class} resolves the request from the container";
            }

            if (in_array('request', self::helperCallsIn($source), true)) {
                $found[] = "{$class} calls request()";
            }

            if (in_array($class, self::REQUEST_READERS, true)) {
                continue;
            }

            if (!in_array('illuminate\http\request', array_map(strtolower(...), self::qualifiedNamesIn($source)), true)) {
                continue;
            }

            $found[] = "{$class} names the request";
        }

        self::assertSame([], $found);

        foreach (self::REQUEST_READERS as $reader) {
            self::assertContains('Illuminate\Http\Request', self::qualifiedNamesIn(self::sources()[$reader]), "{$reader} no longer reads a request.");
        }
    }

    /**
     * The log scan finds Laravel's loggers however named and the log helpers,
     * and skips PSR-3, methods, declarations and lookalikes.
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
     * The sibling scan finds a sibling however it is named, and skips the
     * package's own names and lookalikes.
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
             * Bridges laravel-authentication and laravel-mfa (AUTH-3.10), not
             * laravel-sso (SSO-9.2), laravel-iamish or OAUTH-2.
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
            'laravel-authentication',
            'laravel-mfa',
            'AUTH-3',
        ], self::siblingReferencesIn($source));

        self::assertSame(1, preg_match(self::SIBLING_PACKAGE, 'sinemacula/laravel-authentication'));
        self::assertSame(0, preg_match(self::SIBLING_PACKAGE, 'sinemacula/laravel-sso'));
        self::assertSame(0, preg_match(self::SIBLING_PACKAGE, 'sinemacula/coding-standards-laravel'));
    }

    /**
     * The scanner finds a package name however a class names it, and skips
     * unqualified names, a closure's `use` and names outside the package.
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
     * The scanner gives each bracketed namespace its own imports, and resolves
     * global names from the root.
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
     * A qualified name resolves case-insensitively through class imports only,
     * and a rule catches a forbidden name whatever its case.
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
     * Every file the package ships, by relative path, with its contents.
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
     * The references to a sibling package the text holds, grouped by kind.
     *
     * @param  string  $text
     * @return list<string>
     */
    private static function siblingReferencesIn(string $text): array
    {
        preg_match_all(self::SIBLING_NAMESPACE, $text, $namespaces);
        preg_match_all(self::SIBLING_CONFIG, $text, $config);
        preg_match_all(self::SIBLING_NAME, $text, $names);

        return [...$namespaces[0], ...$config[0], ...$names[0]];
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
     * Every class of the package and the package names it names, read once.
     *
     * @return array<string, list<string>>
     */
    private static function names(): array
    {
        return self::$names ??= array_map(self::namesIn(...), self::sources());
    }

    /**
     * Every class of the package and its source, read once.
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
     * Every distinct fully qualified name the source names, in order of first
     * use; a trait's or closure's `use` counts as code.
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
     * The direct log writers the source names or calls, in order of first use.
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
     * The lower-case names of the plain functions the source calls.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function helperCallsIn(string $source): array
    {
        $tokens = self::tokens($source);
        $calls  = [];

        foreach ($tokens as $index => $token) {

            if (!is_array($token) || !in_array($token[0], [T_STRING, T_NAME_FULLY_QUALIFIED], true)) {
                continue;
            }

            if (($tokens[$index + 1] ?? null) !== '(' || self::isMember($tokens[$index - 1] ?? null)) {
                continue;
            }

            $calls[] = strtolower(ltrim($token[1], '\\'));
        }

        return array_values(array_unique($calls));
    }

    /**
     * Whether the token before a name makes it a member, declaration or `new`.
     *
     * @param  array{0: int, 1: string, 2: int}|string|null  $previous
     * @return bool
     */
    private static function isMember(array|string|null $previous): bool
    {
        return is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION, T_NEW], true);
    }

    /**
     * The namespace declared at the index, its imports' brace depth, and where
     * its body starts.
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
     * Whether the `use` at the index is an import, not a trait's or closure's.
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
     * The import statement at the index, without whitespace, and where it ends.
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
     * The text of the token, spacing the keywords an import may hold.
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
     * The names an import statement imports, recording class and namespace
     * aliases by lower case apart from function and constant imports.
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
     * The import's kind (`function`, `const` or `''` for a class) and the
     * import without that word; a group member inherits its statement's kind.
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
     * The fully qualified name a name token stands for, or `null`.
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
     * Whether the name is in one of the namespaces or classes, ignoring case.
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
