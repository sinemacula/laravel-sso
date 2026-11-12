<?php

declare(strict_types = 1);

namespace Tests\Unit\Benchmarks;

use Benchmarks\Fetching\AddressPolicyBench;
use Benchmarks\Protocols\IdTokenValidationBench;
use Benchmarks\Protocols\SamlValidationBench;
use Benchmarks\Runtime\ServiceProviderBench;
use Benchmarks\Support\BenchApplication;
use Illuminate\Container\Container;
use PhpBench\Attributes\Assert;
use PhpBench\Attributes\BeforeMethods;
use PhpBench\Attributes\ParamProviders;
use PhpBench\Benchmark\Metadata\AnnotationReader;
use PhpBench\Reflection\ReflectionClass;
use PhpBench\Reflection\ReflectionMethod;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Fetching\AddressPolicy;
use SineMacula\Laravel\Sso\Protocols\Completion;
use SineMacula\Laravel\Sso\Protocols\Oidc\IdTokenValidator;
use SineMacula\Laravel\Sso\Protocols\Oidc\Tokens\IdTokenValidation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Validation\AssertionValidator;

/**
 * Runs every bench subject once, untimed, so a broken bench fails CI.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AssertionValidator::class)]
#[CoversClass(IdTokenValidator::class)]
#[CoversClass(AddressPolicy::class)]
final class BenchmarksRunTest extends TestCase
{
    /** @var string What a subject's answer is when it validated its input. */
    private const string VALID = 'valid';

    /** @var string The prefix PHPBench takes a method to be a subject by. */
    private const string SUBJECT = 'bench';

    /**
     * Forget whatever application a bench booted.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        BenchApplication::forget();

        parent::tearDown();
    }

    /**
     * Rows of `[bench, answers]`: each bench and what its subjects answer.
     *
     * @return iterable<string, array{0: class-string, 1: array<string, bool|\SineMacula\Laravel\Sso\Events\Enums\FailureReason|string|null>}>
     */
    public static function provideBenches(): iterable
    {
        yield 'SAML validation' => [SamlValidationBench::class, [
            'benchValidSigned'    => self::VALID,
            'benchValidEncrypted' => self::VALID,
            'benchBadSignature'   => FailureReason::SIGNATURE_INVALID,
            'benchExpired'        => FailureReason::ASSERTION_EXPIRED,
            'benchWrongAudience'  => FailureReason::AUDIENCE_MISMATCH,
        ]];

        yield 'ID token validation' => [IdTokenValidationBench::class, [
            'benchValidRs256'    => self::VALID,
            'benchValidEs256'    => self::VALID,
            'benchBadSignature'  => FailureReason::SIGNATURE_INVALID,
            'benchWrongAudience' => FailureReason::AUDIENCE_MISMATCH,
            'benchExpired'       => FailureReason::ASSERTION_EXPIRED,
        ]];

        yield 'the address policy' => [AddressPolicyBench::class, [
            'benchPublicV4'  => false,
            'benchPublicV6'  => false,
            'benchPrivate'   => true,
            'benchLinkLocal' => true,
            'benchMetadata'  => true,
            'benchMapped'    => true,
        ]];

        yield 'the service provider' => [ServiceProviderBench::class, ['benchRegisterAndBoot' => null]];
    }

    /**
     * Each subject completes and answers what its input calls for.
     *
     * @param  class-string  $bench
     * @param  array<string, bool|\SineMacula\Laravel\Sso\Events\Enums\FailureReason|string|null>  $answers
     * @return void
     */
    #[DataProvider('provideBenches')]
    public function testEverySubjectCompletesAndAnswersItsInput(string $bench, array $answers): void
    {
        self::assertSame(array_keys($answers), self::subjectsOf($bench));

        $prepared = self::prepared($bench);

        foreach ($answers as $subject => $answer) {
            self::assertSame($answer, self::answerOf((new \ReflectionMethod($bench, $subject))->invoke($prepared)), $subject);
        }
    }

    /**
     * The service provider bench leaves the package registered.
     *
     * @return void
     */
    public function testTheServiceProviderBenchRegistersThePackage(): void
    {
        (new ServiceProviderBench)->benchRegisterAndBoot();

        self::assertTrue(Container::getInstance()->bound(Clock::class));
    }

    /**
     * Every bench PHPBench would find is one this test runs.
     *
     * @return void
     */
    public function testEveryBenchClassIsRun(): void
    {
        $run = array_map(static fn (array $row): string => $row[0], iterator_to_array(self::provideBenches(), false));

        sort($run);

        self::assertSame($run, self::benchClasses());
    }

    /**
     * No bench asserts a time: a slow run never fails, in CI or anywhere else.
     *
     * @param  class-string  $bench
     * @param  array<string, bool|\SineMacula\Laravel\Sso\Events\Enums\FailureReason|string|null>  $answers
     * @return void
     */
    #[DataProvider('provideBenches')]
    public function testNoBenchAssertsATime(string $bench, array $answers): void
    {
        unset($answers);

        $class = new \ReflectionClass($bench);

        self::assertSame([], $class->getAttributes(Assert::class));

        foreach ($class->getMethods() as $method) {
            self::assertSame([], $method->getAttributes(Assert::class));
        }
    }

    /**
     * PHPBench parses every doc comment; an unknown tag skips the file quietly.
     *
     * @param  class-string  $bench
     * @param  array<string, bool|\SineMacula\Laravel\Sso\Events\Enums\FailureReason|string|null>  $answers
     * @return void
     */
    #[DataProvider('provideBenches')]
    public function testPhpBenchCanReadEveryDocComment(string $bench, array $answers): void
    {
        unset($answers);

        $reader = new AnnotationReader;
        $native = new \ReflectionClass($bench);
        $class  = new ReflectionClass((string) $native->getFileName(), $bench);

        $class->comment = (string) $native->getDocComment();

        self::assertSame([], $reader->getClassAnnotations($class));

        foreach ($native->getMethods() as $method) {

            $read = new ReflectionMethod;

            $read->reflectionClass = $class;
            $read->class           = $bench;
            $read->name            = $method->getName();
            $read->comment         = (string) $method->getDocComment();

            self::assertSame([], $reader->getMethodAnnotations($read), $method->getName());
        }
    }

    /**
     * A protocol bench records the versions its times depend on.
     *
     * @return void
     */
    public function testAProtocolBenchRecordsItsDependencyVersions(): void
    {
        $saml = (new SamlValidationBench)->provideVersions();
        $oidc = (new IdTokenValidationBench)->provideVersions();

        self::assertCount(1, $saml);
        self::assertCount(1, $oidc);

        $samlVersions = reset($saml);
        $oidcVersions = reset($oidc);

        self::assertIsArray($samlVersions);
        self::assertIsArray($oidcVersions);
        self::assertSame(['simplesamlphp/saml2', 'simplesamlphp/xml-security', 'laravel/framework'], array_keys($samlVersions));
        self::assertSame(['web-token/jwt-library', 'laravel/framework'], array_keys($oidcVersions));
        self::assertNotContains('unknown', $samlVersions);
        self::assertNotContains('unknown', $oidcVersions);
        self::assertStringStartsWith('simplesamlphp/saml2 ', key($saml));
        self::assertStringStartsWith('web-token/jwt-library ', key($oidc));
    }

    /**
     * A protocol bench declares the parameter set that provides its versions.
     *
     * @return void
     */
    public function testAProtocolBenchDeclaresItsParameterSet(): void
    {
        foreach ([SamlValidationBench::class, IdTokenValidationBench::class] as $bench) {
            $attributes = (new \ReflectionClass($bench))->getAttributes(ParamProviders::class);

            self::assertSame(['provideVersions'], $attributes[0]->newInstance()->providers);
        }
    }

    /**
     * The bench with its `#[BeforeMethods]` run, as PHPBench prepares it.
     *
     * @param  class-string  $bench
     * @return object
     */
    private static function prepared(string $bench): object
    {
        $prepared = new $bench;

        foreach ((new \ReflectionClass($bench))->getAttributes(BeforeMethods::class) as $attribute) {
            foreach ($attribute->newInstance()->methods as $method) {
                (new \ReflectionMethod($bench, $method))->invoke($prepared);
            }
        }

        return $prepared;
    }

    /**
     * The bench's subjects, in the order it declares them.
     *
     * @param  class-string  $bench
     * @return list<string>
     */
    private static function subjectsOf(string $bench): array
    {
        return array_values(array_filter(get_class_methods($bench), static fn (string $method): bool => str_starts_with($method, self::SUBJECT)));
    }

    /**
     * A validator's verdict as `valid` or its reason; anything else as is.
     *
     * @param  mixed  $outcome
     * @return bool|\SineMacula\Laravel\Sso\Events\Enums\FailureReason|string|null
     */
    private static function answerOf(mixed $outcome): bool|FailureReason|string|null
    {
        return match (true) {
            $outcome instanceof Completion        => $outcome->isVerified() ? self::VALID : $outcome->reason,
            $outcome instanceof IdTokenValidation => $outcome->isValidated() ? self::VALID : $outcome->reason,
            is_bool($outcome)                     => $outcome,
            default                               => null,
        };
    }

    /**
     * Every bench class under the bench path, sorted.
     *
     * @return list<string>
     */
    private static function benchClasses(): array
    {
        $root    = dirname(__DIR__, 3) . '/benchmarks/';
        $classes = [];

        /** @var \SplFileInfo $file */
        foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)) as $file) {
            if (!str_ends_with($file->getPathname(), 'Bench.php')) {
                continue;
            }

            $classes[] = 'Benchmarks\\' . str_replace('/', '\\', substr($file->getPathname(), strlen($root), -strlen('.php')));
        }

        sort($classes);

        return $classes;
    }
}
