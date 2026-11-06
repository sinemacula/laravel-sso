<?php

declare(strict_types = 1);

namespace Tests\Integration\Connections;

use Illuminate\Database\QueryException;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Connections\ConnectionSecrets;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Concerns\RecordsEventSequences;
use Tests\Fixtures\FixedClock;
use Tests\Fixtures\Freshness\RecordingFreshness;
use Tests\TestCase;

/**
 * Integration tests, on a real database, of what the management helpers store
 * (SSO-2.5, SSO-11.3, SSO-11.4): the settings hold no secret, the secrets
 * column holds only ciphertext that the bound encrypter decrypts, before and
 * after `app.key` is rotated; an encrypter that cannot encrypt propagates with
 * nothing written; a failed write quotes no ciphertext; no exception's trace
 * carries a secret given; and every read is made on the write connection.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConnectionService::class)]
#[CoversClass(ConnectionSecrets::class)]
#[CoversClass(CiphertextWrite::class)]
final class ConnectionServiceTest extends TestCase
{
    use RecordsEventSequences;

    /** @var string The tenant the connections belong to. */
    private const string TENANT = 'tenant-1';

    /** @var string A client secret no stored value may show. */
    private const string SECRET = 'the-client-secret-value';

    /** @var string Another client secret no trace may show. */
    private const string OTHER_SECRET = 'the-other-client-secret';

    /** @var string The failure of a write of the secrets, with the SQLSTATE the driver gave. */
    private const string SECRETS_NOT_WRITTEN = '/^The connection\'s secrets could not be written \(SQLSTATE [0-9A-Z]{5}\)\.$/';

    /** @var string The key the secret is first encrypted under. */
    private const string KEY_A = 'base64:QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=';

    /** @var string The key it is rotated to. */
    private const string KEY_B = 'base64:QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=';

    /** @var array<string, string> The settings of a complete OIDC connection. */
    private const array OIDC = [
        'issuer'                 => 'https://idp.example.com',
        'authorization_endpoint' => 'https://idp.example.com/authorize',
        'token_endpoint'         => 'https://idp.example.com/token',
        'jwks_uri'               => 'https://idp.example.com/jwks',
        'client_id'              => 'client-123',
    ];

    /**
     * Bind a fixed clock and a fresh freshness contract, turn OIDC on, create
     * the tables, and record events.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->app?->instance(Clock::class, new FixedClock('2026-11-01T09:30:00Z'));
        $this->app?->instance(Freshness::class, new RecordingFreshness);

        config()->set('sso.features.oidc', true);

        $this->usePackageTables();
        $this->startRecordingEvents();
    }

    /**
     * The row holds the settings with no secret, and the secret only as
     * ciphertext the bound encrypter decrypts.
     *
     * @return void
     */
    public function testStoresTheSecretOnlyAsCiphertext(): void
    {
        $id  = $this->create();
        $row = $this->row($id);

        self::assertIsString($row['settings']);
        self::assertIsString($row['secrets']);
        self::assertStringNotContainsString(self::SECRET, $row['settings']);
        self::assertStringNotContainsString(self::SECRET, $row['secrets']);
        self::assertSame(self::TENANT, $row['tenant_id']);
        self::assertSame('oidc', $row['protocol']);
        self::assertSame('Acme', $row['display_name']);
        self::assertFalse((bool) $row['enabled']);
        self::assertFalse((bool) $row['has_completed_sign_in']);
        self::assertIsString($row['created_at']);
        self::assertStringStartsWith('2026-11-01 09:30:00', $row['created_at']);

        $settings = json_decode($row['settings'], true);

        self::assertIsArray($settings);
        self::assertArrayNotHasKey('client_secret', $settings);
        self::assertSame(self::OIDC['issuer'], $settings['issuer']);
        self::assertSame('client_secret_basic', $settings['client_authentication']);

        $secrets = json_decode($row['secrets'], true);

        self::assertIsArray($secrets);
        self::assertSame(['client_secret'], array_keys($secrets));
        self::assertIsString($secrets['client_secret']);
        self::assertSame(self::SECRET, $this->encrypter()->decrypt($secrets['client_secret']));
    }

    /**
     * A secret stored before `app.key` is rotated still decrypts while the old
     * key is a previous one, is kept by an update that does not name it, and a
     * secret set afterwards is encrypted under the new key.
     *
     * @return void
     */
    public function testSecretsSurviveAnAppKeyRotation(): void
    {
        $this->useKeys(self::KEY_A, []);

        $id     = $this->create();
        $stored = $this->row($id)['secrets'];

        $this->useKeys(self::KEY_B, [self::KEY_A]);

        self::assertTrue($this->secrets()->reveal($this->connection($id), 'client_secret')?->equals(self::SECRET));
        self::assertTrue($this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed'])->isSucceeded());
        self::assertSame($stored, $this->row($id)['secrets']);

        self::assertTrue($this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => 'the-rotated-secret']])->isSucceeded());

        $this->useKeys(self::KEY_B, []);

        self::assertTrue($this->secrets()->reveal($this->connection($id), 'client_secret')?->equals('the-rotated-secret'));
    }

    /**
     * An encrypter that cannot encrypt propagates as a server error, and
     * nothing is written or reported.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAnEncrypterThatCannotEncryptPropagates(): void
    {
        $id     = $this->create();
        $before = $this->row($id);

        $this->startRecordingEvents();

        $this->app?->instance(SecretEncrypter::class, new class implements SecretEncrypter {
            /**
             * Fail.
             *
             * @param  string  $secret
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                unset($secret);

                throw new \RuntimeException('The key management service is unavailable.');
            }

            /**
             * Never called.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                return $ciphertext;
            }
        });

        $calls = [
            fn (): mixed => $this->service()->create(self::TENANT, 'oidc', 'Second', self::OIDC + ['client_secret' => self::SECRET]),
            fn (): mixed => $this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed', 'settings' => ['client_secret' => 'another-secret']]),
        ];

        foreach ($calls as $call) {

            try {
                $call();
                self::fail('The encrypter\'s failure was swallowed.');
            } catch (\RuntimeException $exception) {
                self::assertSame('The key management service is unavailable.', $exception->getMessage());
            }
        }

        self::assertSame(1, DB::table('sso_connections')->count());
        self::assertSame($before, $this->row($id));
        $this->assertNoEvents();
    }

    /**
     * A failed write of the secrets propagates as a server error that quotes no
     * ciphertext and chains nothing that does, with nothing written; a failed
     * write that binds no secret is Laravel's own `QueryException`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAFailedWriteNeverQuotesTheCiphertext(): void
    {
        $id     = $this->create();
        $before = $this->row($id);

        Schema::connection(StorageConnection::name())->table((new Connection)->getTable(), static function (Blueprint $table): void {
            $table->dropColumn('updated_at');
        });

        $this->startRecordingEvents();

        $calls = [
            fn (): mixed => $this->service()->create(self::TENANT, 'oidc', 'Second', self::OIDC + ['client_secret' => self::SECRET]),
            fn (): mixed => $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => self::OTHER_SECRET]]),
        ];

        foreach ($calls as $call) {

            try {
                $call();
                self::fail('The failed write was swallowed.');
            } catch (\RuntimeException $exception) {
                self::assertNotInstanceOf(QueryException::class, $exception);
                self::assertMatchesRegularExpression(self::SECRETS_NOT_WRITTEN, $exception->getMessage());
                self::assertNull($exception->getPrevious());
            }
        }

        try {
            $this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed']);
            self::fail('The failed write was swallowed.');
        } catch (QueryException $exception) {
            self::assertIsString($before['secrets']);
            self::assertStringNotContainsString($before['secrets'], $exception->getMessage());
        }

        self::assertSame(1, DB::table('sso_connections')->count());
        self::assertSame(array_diff_key($before, ['updated_at' => true]), $this->row($id));
        $this->assertNoEvents();
    }

    /**
     * No exception's trace carries a secret an administrator gave, even with
     * arguments collected (`zend.exception_ignore_args` off): every parameter
     * that holds one is `#[\SensitiveParameter]`. Shown for a refused tenant
     * id, an encrypter that cannot encrypt, and a failed write.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testNoTraceCarriesASecretGiven(): void
    {
        $id      = $this->create();
        $setting = ini_get('zend.exception_ignore_args');

        ini_set('zend.exception_ignore_args', '0');

        try {
            $traces = [
                ...$this->tracesOf($id, 'refused tenant'),
                ...$this->tracesOf($id, 'failed write', static function (): void {
                    Schema::connection(StorageConnection::name())->table((new Connection)->getTable(), static function (Blueprint $table): void {
                        $table->dropColumn('updated_at');
                    });
                }),
                ...$this->tracesOf($id, 'failing encrypter', $this->failingEncrypter(...)),
            ];
        } finally {
            ini_set('zend.exception_ignore_args', (string) $setting);
        }

        self::assertCount(10, $traces);

        foreach ($traces as $call => $trace) {
            self::assertNotSame([], $trace, $call);
            self::assertFalse(self::carriesASecret($trace), "The trace of {$call} carries a secret.");
        }
    }

    /**
     * Every read is made on the write connection: with the read connection
     * unusable, every helper still answers.
     *
     * @return void
     */
    public function testReadsTheWriteConnection(): void
    {
        $id = $this->create();

        DB::connection()->setReadPdo(static function (): never {
            throw new \LogicException('The read connection was used.');
        });

        try {
            $updated = $this->service()->update(self::TENANT, $id, ['display_name' => 'Renamed']);
            $enabled = $this->service()->enable(self::TENANT, $id);
            $found   = $this->service()->get(self::TENANT, $id);
            $listed  = $this->service()->list(self::TENANT);
        } finally {
            DB::connection()->setReadPdo(null);
        }

        self::assertTrue($updated->isSucceeded());
        self::assertTrue($enabled->isSucceeded());
        self::assertSame('Renamed', $found?->displayName);
        self::assertCount(1, $listed);
    }

    /**
     * Create a complete OIDC connection named `Acme` with its client secret.
     *
     * @return string
     */
    private function create(): string
    {
        $result = $this->service()->create(self::TENANT, 'oidc', 'Acme', self::OIDC + ['client_secret' => self::SECRET]);

        self::assertTrue($result->isSucceeded());

        return (string) $result->connection?->id;
    }

    /**
     * The trace of each helper given a secret, each of which must throw: a
     * creation and an update for an empty tenant id and, once a preparation
     * that makes them fail has run, for the tenant.
     *
     * @param  string  $id
     * @param  string  $label
     * @param  ?\Closure(): void  $prepare
     * @return array<string, list<array<string, mixed>>>
     *
     * @throws \Throwable
     */
    private function tracesOf(string $id, string $label, ?\Closure $prepare = null): array
    {
        if ($prepare !== null) {
            $prepare();
        }

        $calls = [
            'create'               => fn (): mixed => $this->service()->create(self::TENANT, 'oidc', 'Second', self::OIDC + ['client_secret' => self::SECRET]),
            'update'               => fn (): mixed => $this->service()->update(self::TENANT, $id, ['settings' => ['client_secret' => self::OTHER_SECRET]]),
            'create for no tenant' => fn (): mixed => $this->service()->create('', 'oidc', 'Second', self::OIDC + ['client_secret' => self::SECRET]),
            'update for no tenant' => fn (): mixed => $this->service()->update('', $id, ['settings' => ['client_secret' => self::OTHER_SECRET]]),
        ];

        if ($prepare === null) {
            unset($calls['create'], $calls['update']);
        }

        $traces = [];

        foreach ($calls as $name => $call) {

            $thrown = null;

            try {
                $call();
            } catch (\InvalidArgumentException|\RuntimeException $exception) {
                $thrown = $exception;
            }

            self::assertNotNull($thrown, "{$label}: {$name} did not throw.");

            $traces["{$label}: {$name}"] = $thrown->getTrace();
        }

        return $traces;
    }

    /**
     * Bind an encrypter that cannot encrypt.
     *
     * @return void
     */
    private function failingEncrypter(): void
    {
        $this->app?->instance(SecretEncrypter::class, new class implements SecretEncrypter {
            /**
             * Fail.
             *
             * @param  string  $secret
             * @return string
             *
             * @throws \RuntimeException
             */
            #[\Override]
            public function encrypt(#[\SensitiveParameter] string $secret): string
            {
                unset($secret);

                throw new \RuntimeException('The key management service is unavailable.');
            }

            /**
             * Never called.
             *
             * @param  string  $ciphertext
             * @return string
             */
            #[\Override]
            public function decrypt(string $ciphertext): string
            {
                return $ciphertext;
            }
        });
    }

    /**
     * Whether any argument of the trace, however deeply nested in an array,
     * holds either secret given.
     *
     * @param  mixed  $value
     * @return bool
     */
    private static function carriesASecret(mixed $value): bool
    {
        if (is_string($value)) {
            return str_contains($value, self::SECRET) || str_contains($value, self::OTHER_SECRET);
        }

        foreach (is_array($value) ? $value : [] as $nested) {
            if (self::carriesASecret($nested)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The connection's row, as stored.
     *
     * @param  string  $id
     * @return array<string, mixed>
     */
    private function row(string $id): array
    {
        $row = DB::table('sso_connections')->where('id', $id)->first();

        self::assertIsObject($row);

        return (array) $row;
    }

    /**
     * The connection, read through the model.
     *
     * @param  string  $id
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function connection(string $id): Connection
    {
        return Connection::query()->findOrFail($id);
    }

    /**
     * The management helpers, resolved per request.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionService
     */
    private function service(): ConnectionService
    {
        $service = $this->app?->make(ConnectionService::class);

        self::assertInstanceOf(ConnectionService::class, $service);

        return $service;
    }

    /**
     * The connections' secrets, through the bound encrypter.
     *
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionSecrets
     */
    private function secrets(): ConnectionSecrets
    {
        $secrets = $this->app?->make(ConnectionSecrets::class);

        self::assertInstanceOf(ConnectionSecrets::class, $secrets);

        return $secrets;
    }

    /**
     * The bound secret encrypter.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SecretEncrypter
     */
    private function encrypter(): SecretEncrypter
    {
        $encrypter = $this->app?->make(SecretEncrypter::class);

        self::assertInstanceOf(SecretEncrypter::class, $encrypter);

        return $encrypter;
    }

    /**
     * Set the application key and its previous keys, and forget Laravel's
     * encrypter and the scoped instances, so the next resolution reads them.
     *
     * @param  string  $key
     * @param  list<string>  $previous
     * @return void
     */
    private function useKeys(string $key, array $previous): void
    {
        config()->set('app.key', $key);
        config()->set('app.previous_keys', $previous);

        $this->app?->forgetInstance('encrypter');
        $this->app?->forgetScopedInstances();
    }
}
