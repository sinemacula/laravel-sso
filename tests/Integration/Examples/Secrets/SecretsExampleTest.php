<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Secrets;

use Illuminate\Support\Facades\Artisan;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Contracts\Fetcher;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;
use SineMacula\Laravel\Sso\Secrets\SecretsCheck;
use SineMacula\Laravel\Sso\Testing\FakeOpenIdProvider;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The examples of `docs/guides/secrets.md`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConstantTime::class)]
#[CoversClass(SecretsCheck::class)]
final class SecretsExampleTest extends ExampleTestCase
{
    /** @var string The secret the comparisons know. */
    private const string KNOWN = 'a-known-secret';

    /** @var string The value the stored digests are of. */
    private const string PRESENTED = 'a-presented-verifier';

    /** @var \Tests\Integration\Examples\Secrets\KmsClient The application's KMS. */
    private KmsClient $kms;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the KMS with the `sso-secrets` key, and the person.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->kms    = new KmsClient('sso-secrets');
        $this->person = new IdentityReference('App\Models\User', 'person-1');

        $this->instance(KmsClient::class, $this->kms);
    }

    /**
     * The application's encrypter replaces the default, one per request or job.
     *
     * @return void
     */
    public function testTheApplicationsEncrypterReplacesTheDefaultScoped(): void
    {
        $this->deployTheApplicationsEncrypter();

        $encrypter = app(SecretEncrypter::class);

        self::assertInstanceOf(KmsSecretEncrypter::class, $encrypter);
        self::assertSame($encrypter, app(SecretEncrypter::class));

        app()->forgetScopedInstances();

        self::assertInstanceOf(KmsSecretEncrypter::class, app(SecretEncrypter::class));
        self::assertNotSame($encrypter, app(SecretEncrypter::class));
    }

    /**
     * The KMS keeps the client secret, and the flow's token exchange uses it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheServiceKeepsTheClientSecretAndTheFlowCompletes(): void
    {
        $this->deployTheApplicationsEncrypter();

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        self::assertSame(1, $this->kms->requests());

        $linked = $this->linkThroughFlow($provider, $connectionId, $this->person);

        self::assertSame($connectionId, $linked->result?->connectionId);
        self::assertNotNull($linked->linkId);
        self::assertGreaterThan(1, $this->kms->requests());
    }

    /**
     * After a key rotation the secret stored before still decrypts.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheEncrypterKeepsDecryptingAfterTheServiceRotatesItsKey(): void
    {
        $this->deployTheApplicationsEncrypter();

        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);
        $encrypter    = app(SecretEncrypter::class);
        $before       = $encrypter->encrypt(FakeOpenIdProvider::CLIENT_SECRET);

        $this->kms->rotate('sso-secrets');

        $after = $encrypter->encrypt(FakeOpenIdProvider::CLIENT_SECRET);

        self::assertStringStartsWith('sso-secrets:0:', $before);
        self::assertStringStartsWith('sso-secrets:1:', $after);
        self::assertSame(FakeOpenIdProvider::CLIENT_SECRET, $encrypter->decrypt($before));
        self::assertSame(FakeOpenIdProvider::CLIENT_SECRET, $encrypter->decrypt($after));
        self::assertTrue($this->linkThroughFlow($provider, $connectionId, $this->person)->isRedeemed());
    }

    /**
     * A foreign ciphertext throws without revealing it, never decrypting to a
     * wrong value.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACiphertextTheServiceDidNotIssueIsRefused(): void
    {
        $this->deployTheApplicationsEncrypter();

        $encrypter = app(SecretEncrypter::class);
        $issued    = $encrypter->encrypt(FakeOpenIdProvider::CLIENT_SECRET);
        $sealed    = explode(':', $issued, 3)[2];
        $answers   = [];

        foreach (['sso-secrets:0:' . base64_encode(random_bytes(48)), "sso-secrets:7:{$sealed}", "other-key:0:{$sealed}"] as $ciphertext) {
            try {
                $answers[] = $encrypter->decrypt($ciphertext);
            } catch (\RuntimeException $exception) {
                $answers[] = $exception->getMessage();
            }
        }

        self::assertSame(array_fill(0, 3, 'The key management service cannot decrypt the ciphertext.'), $answers);
    }

    /**
     * A secret stored under `APP_KEY` is a server error after switching to the
     * KMS, never a failed sign-in.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testASecretStoredUnderAnotherEncrypterIsAServerError(): void
    {
        $provider     = new FakeOpenIdProvider(clock: $this->clock);
        $connectionId = $this->makeOidcConnection($provider);

        self::assertSame(0, $this->kms->requests());

        $this->deployTheApplicationsEncrypter();

        $start = $this->startFlow(Purpose::LINK, $connectionId, $this->person);

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('The key management service cannot decrypt the ciphertext.');

        $this->respondAtProvider($provider, $connectionId, $start);
    }

    /**
     * `sso:check` reports `[secrets]` working without calling the KMS.
     *
     * @return void
     */
    public function testTheCheckResolvesTheEncrypterWithoutCallingTheService(): void
    {
        $this->deployTheApplicationsEncrypter();

        Artisan::call('sso:check');

        self::assertStringContainsString('[secrets] OK', Artisan::output());
        self::assertSame(0, $this->kms->requests());
    }

    /**
     * The secret and both digests match only their own value.
     *
     * @return void
     */
    public function testTheComparisonsMatchOnlyTheKnownValue(): void
    {
        self::assertSame([true, true, true], self::compared(self::KNOWN, self::PRESENTED));
        self::assertSame([false, false, false], self::compared('a-known-secreT', 'a-presented-verifieR'));
        self::assertSame([false, false, false], self::compared('', ''));
    }

    /**
     * A digest by a non-cryptographic algorithm is refused, naming it.
     *
     * @return void
     */
    public function testADigestByANonCryptographicAlgorithmIsRefused(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The digest algorithm [crc32b] is not a cryptographic hash PHP supports.');

        ConstantTime::matchesDigest(hash('crc32b', self::PRESENTED), self::PRESENTED, 'crc32b');
    }

    /**
     * Run the comparisons against the known secret and the presented value's
     * digests.
     *
     * @param  string  $given
     * @param  string  $presented
     * @return mixed
     */
    private static function compared(string $given, string $presented): mixed
    {
        return self::comparing([
            'known'           => self::KNOWN,
            'given'           => $given,
            'storedSha256Hex' => hash('sha256', self::PRESENTED),
            'storedSha512Hex' => hash('sha512', self::PRESENTED),
            'presented'       => $presented,
        ]);
    }

    /**
     * The comparisons' script, given its input.
     *
     * @param  array<string, string>  $input
     * @return mixed
     */
    private static function comparing(array $input): mixed
    {
        return require __DIR__ . '/compare.php';
    }

    /**
     * Register the application's provider and begin a new request, so nothing
     * scoped under the default encrypter is reused; the fakes are rebound.
     *
     * @return void
     */
    private function deployTheApplicationsEncrypter(): void
    {
        app()->register(AppServiceProvider::class);
        app()->forgetScopedInstances();

        $this->instance(Fetcher::class, $this->fetcher);
        $this->instance(DnsResolver::class, $this->dns);
    }
}
