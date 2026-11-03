<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Logging;

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\File;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer;
use SineMacula\Laravel\Sso\Logging\LoggingCheck;
use SineMacula\Laravel\Sso\Logging\LoggingSettings;
use SineMacula\Laravel\Sso\Logging\Redactor;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/logging.md` (SSO-5.7, SSO-9.8, SSO-11.9,
 * SSO-12.5), on the shared example harness: the `sso` channel the application's
 * `config/logging.php` configures and `SSO_LOG_CHANNEL` names, the logging
 * settings its published `config/sso.php` holds, and its own secret encrypter
 * logging a refusal of its key management service through the package's logger.
 * Each reads what the daily file of the channel holds, under a storage
 * directory of the test's own, and asserts a refusal: a channel no
 * `logging.channels` configures, a malformed list of redacted keys, a
 * diagnostic length out of range, and a key management service that refuses to
 * decrypt.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SanitizingLogger::class)]
#[CoversClass(LoggingSettings::class)]
#[CoversClass(LoggingCheck::class)]
#[CoversClass(DiagnosticSanitizer::class)]
#[CoversClass(Redactor::class)]
final class LoggingExampleTest extends ExampleTestCase
{
    /** @var list<string> The environment variables the published settings read. */
    private const array VARIABLES = ['SSO_LOG_CHANNEL', 'SSO_LOG_MAX_DIAGNOSTIC_LENGTH'];

    /** @var string The API key the key management service client carries. */
    private const string API_KEY = 'k-3f9a2c';

    /** @var string The problem `sso:check` reports for the `sso` channel while no `logging.channels` configures it. */
    private const string UNCONFIGURED_CHANNEL = '[logging] `sso.logging.channel` names the channel [sso], which is not configured in `logging.channels`.';

    /** @var string A line in a log file: its level, its message, and its context as JSON, if any. */
    private const string LINE = '/^\[[^\]]+\] [^.\s]+\.(?<level>[A-Z]+): (?<message>.*?)(?: (?<context>\{.*\}|\[\]))?\s*$/';

    /** @var ?string The application's storage directory, which the test removes. */
    private ?string $storage = null;

    /** @var \Tests\Integration\Examples\Logging\KmsClient The application's key management service client. */
    private KmsClient $kms;

    /**
     * Give the application a storage directory of the test's own, so the log
     * files it writes are the test's alone, and make the key management service
     * client.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->storage = sys_get_temp_dir() . '/sso-logging-' . bin2hex(random_bytes(8));
        $this->kms     = new KmsClient('alias/sso', self::API_KEY);

        app()->useStoragePath($this->storage);
    }

    /**
     * Unset the variables a test set in the environment and remove the storage
     * directory.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        foreach (self::VARIABLES as $variable) {
            putenv($variable);
        }

        if ($this->storage !== null) {
            File::deleteDirectory($this->storage);
        }

        parent::tearDown();
    }

    /**
     * With `SSO_LOG_CHANNEL=sso` and the `sso` channel configured, a provider's
     * error is logged to that channel's daily file, by its code alone, naming
     * the request by the public reference its failure redirect names.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testThePackageLogsToTheChannelItIsGiven(): void
    {
        putenv('SSO_LOG_CHANNEL=sso');
        $this->publishChannel();
        $this->publishSettings();

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $start        = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $query        = $provider->authorize($start)->errorQuery('access_denied', 'The user cancelled the sign-in.');
        $result       = app(CompletionService::class)->callback($connectionId, new CompletionRequest('GET', $query, []));
        $redirect     = HandoffRedirect::from(app(CompletionResponses::class)->from($result, 'GET'));

        self::assertSame(FailureReason::PROVIDER_ERROR->value, $redirect->error);
        self::assertSame($start->reference?->value, $redirect->reference);
        self::assertSame([
            ['level' => 'NOTICE', 'context' => ['connection_id' => $connectionId, 'error' => 'access_denied', 'request_reference' => $redirect->reference]],
        ], $this->logged('sso.oidc.callback_error'));
    }

    /**
     * `sso:check` reports `SSO_LOG_CHANNEL=sso` while `logging.channels`
     * configures no `sso` channel, with the guide's message, and reports
     * logging as sound once the channel is configured.
     *
     * @return void
     */
    public function testAChannelNotConfiguredIsReported(): void
    {
        putenv('SSO_LOG_CHANNEL=sso');
        $this->publishSettings();

        [$code, $output] = self::checked();

        self::assertSame(1, $code);
        self::assertContains(self::UNCONFIGURED_CHANNEL, $output);
        self::assertNotContains('[logging] OK', $output);

        $this->publishChannel();

        [, $output] = self::checked();

        self::assertContains('[logging] OK', $output);
        self::assertNotContains(self::UNCONFIGURED_CHANNEL, $output);
    }

    /**
     * An added redacted key is redacted wherever it is logged, in the message
     * and as a context key, where the built-in keys alone leave it in clear;
     * a list of redacted keys holding a name with no letter or digit refuses
     * the log call with the guide's message.
     *
     * @return void
     */
    public function testAddedKeysAreRedacted(): void
    {
        putenv('SSO_LOG_CHANNEL=sso');
        $this->publishChannel();
        $this->publishSettings();

        $logger  = app(SanitizingLogger::class);
        $message = 'The tenant API refused the call with x-api-key=' . self::API_KEY;
        $context = ['x-api-key' => self::API_KEY, 'tenant' => self::TENANT];

        config()->set('sso.logging.redacted_keys', []);

        $logger->warning($message, $context);

        $this->publishSettings();

        $logger->warning($message, $context);

        self::assertSame([
            ['level' => 'WARNING', 'context' => ['tenant' => self::TENANT, 'x-api-key' => self::API_KEY]],
        ], $this->logged($message));
        self::assertSame([
            ['level' => 'WARNING', 'context' => ['tenant' => self::TENANT, 'x-api-key' => '[redacted]']],
        ], $this->logged('The tenant API refused the call with x-api-key=[redacted]'));

        config()->set('sso.logging.redacted_keys', ['x-api-key', '--']);

        $this->expectExceptionObject(new \InvalidArgumentException('`sso.logging.redacted_keys` must be a list of key names, each holding a letter or a digit.'));

        $logger->warning($message, $context);
    }

    /**
     * `SSO_LOG_MAX_DIAGNOSTIC_LENGTH` caps every string logged, ending a cut
     * one in `…`; a length out of range refuses the log call with the guide's
     * message.
     *
     * @return void
     */
    public function testTheDiagnosticLengthCapsWhatIsLogged(): void
    {
        putenv('SSO_LOG_CHANNEL=sso');
        putenv('SSO_LOG_MAX_DIAGNOSTIC_LENGTH=64');
        $this->publishChannel();
        $this->publishSettings();

        $logger = app(SanitizingLogger::class);

        $logger->notice(str_repeat('word ', 30));

        self::assertSame([['level' => 'NOTICE', 'context' => []]], $this->logged(str_repeat('word ', 12) . 'wor…'));

        putenv('SSO_LOG_MAX_DIAGNOSTIC_LENGTH=32');
        $this->publishSettings();

        $this->expectExceptionObject(new \InvalidArgumentException('sso.logging.max_diagnostic_length must be an integer from 64 to 4096.'));

        $logger->notice('Never written.');
    }

    /**
     * The application's own secret encrypter carries a flow while its key
     * management service answers, each of the package's secrets kept there; once
     * the service refuses, decrypting fails as a server error, and the refusal
     * reaches the `sso` channel as the exception's class, redacted message and
     * code, never the API key or a trace.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnAdaptersFailureIsLoggedThroughThePackagesLogger(): void
    {
        putenv('SSO_LOG_CHANNEL=sso');
        $this->publishChannel();
        $this->publishSettings();

        $this->instance(KmsClient::class, $this->kms);
        app()->scoped(SecretEncrypter::class, KmsSecretEncrypter::class);

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        self::assertTrue($this->linkThroughFlow($provider, $connectionId, new IdentityReference('App\Models\User', 'person-1'))->isRedeemed());
        self::assertGreaterThan(0, $this->kms->kept());

        $encrypter  = app(SecretEncrypter::class);
        $ciphertext = $encrypter->encrypt('a tenant secret');

        self::assertSame('a tenant secret', $encrypter->decrypt($ciphertext));

        $this->kms->revoke();

        $thrown = null;

        try {
            $encrypter->decrypt($ciphertext);
        } catch (\RuntimeException $exception) {
            $thrown = $exception;
        }

        self::assertInstanceOf(\RuntimeException::class, $thrown);
        self::assertSame('The secret could not be decrypted.', $thrown->getMessage());
        self::assertInstanceOf(KmsException::class, $thrown->getPrevious());
        self::assertSame([
            ['level' => 'ERROR', 'context' => ['exception' => [
                'class'   => KmsException::class,
                'code'    => KmsClient::ACCESS_DENIED,
                'message' => 'Decrypt on alias/sso was refused for x-api-key=[redacted]',
            ]]],
        ], $this->logged('KMS decrypt failed.'));
        self::assertStringNotContainsString(self::API_KEY, $this->written());
        self::assertStringNotContainsString('#0 ', $this->written());
    }

    /**
     * Lay the guide's `config/logging.php` channels over the application's, as
     * the application's own file configures them.
     *
     * @return void
     */
    private function publishChannel(): void
    {
        /** @var array{channels: array<string, array<string, mixed>>} $published */
        $published = require __DIR__ . '/config/logging.php';

        /** @var array<string, array<string, mixed>> $channels */
        $channels = config('logging.channels');

        config()->set('logging.channels', array_replace($channels, $published['channels']));
    }

    /**
     * Lay the guide's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's, reading the
     * environment as it is now.
     *
     * @return void
     */
    private function publishSettings(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Every line of the `sso` channel's daily files with the message, in order:
     * its level and its context, the context's keys sorted, since the order
     * JSON writes them in is not the guide's to promise.
     *
     * @param  string  $message
     * @return list<array{level: string, context: array<array-key, mixed>}>
     */
    private function logged(string $message): array
    {
        $lines = [];

        foreach (explode("\n", $this->written()) as $line) {

            if (preg_match(self::LINE, $line, $parts) !== 1 || $parts['message'] !== $message) {
                continue;
            }

            /** @var array<array-key, mixed> $context */
            $context = ($parts['context'] ?? '') !== '' ? json_decode($parts['context'], true, flags: JSON_THROW_ON_ERROR) : [];

            $lines[] = ['level' => $parts['level'], 'context' => self::sorted($context)];
        }

        return $lines;
    }

    /**
     * Everything the `sso` channel's daily files hold.
     *
     * @return string
     */
    private function written(): string
    {
        $files = glob($this->storage . '/logs/sso-*.log') ?: [];

        sort($files);

        return implode('', array_map(static fn (string $file): string => (string) file_get_contents($file), $files));
    }

    /**
     * The array with its keys sorted, at every depth.
     *
     * @param  array<array-key, mixed>  $values
     * @return array<array-key, mixed>
     */
    private static function sorted(array $values): array
    {
        ksort($values);

        return array_map(static fn (mixed $value): mixed => is_array($value) ? self::sorted($value) : $value, $values);
    }

    /**
     * Run `sso:check`, and answer its exit code and its lines.
     *
     * @return array{0: int, 1: list<string>}
     */
    private static function checked(): array
    {
        $code  = Artisan::call('sso:check');
        $lines = array_filter(array_map(trim(...), explode("\n", Artisan::output())), static fn (string $line): bool => $line !== '');

        return [$code, array_values($lines)];
    }
}
