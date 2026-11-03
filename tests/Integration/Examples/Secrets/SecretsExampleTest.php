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
 * The examples of `docs/guides/secrets.md` (SSO-2.5, SSO-11.9, SSO-12.5), on
 * the shared example harness: the application's own secret encrypter, keeping
 * the package's secrets under its key management service, bound scoped in its
 * service provider in place of the default; and its own comparisons in constant
 * time.
 *
 * The encrypter is asserted through a whole OIDC flow: the connection's client
 * secret is encrypted by the service when it is set, and the fake token
 * endpoint authenticates the client only when the service decrypts exactly that
 * secret, before and after the service rotates its key. A secret stored under
 * another encrypter is a server error, a `RuntimeException`, never a failed
 * sign-in; and the configuration check resolves the encrypter without calling
 * the service.
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

    /** @var \Tests\Integration\Examples\Secrets\KmsClient The application's key management service. */
    private KmsClient $kms;

    /** @var \SineMacula\Laravel\Sso\Identities\IdentityReference The person the application knows. */
    private IdentityReference $person;

    /**
     * Make the key management service, with the key the package's secrets are
     * kept under, and the person.
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
     * The application's encrypter, bound by its service provider after the
     * package's, replaces the default, scoped: one instance within a request or
     * job, a new one for the next.
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
     * The client secret set on a connection is encrypted by the service, and
     * decrypted by it to exactly the secret given when the flow exchanges its
     * code: the token endpoint authenticates the client, and the flow links.
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
     * After the service rotates its key, a new secret is encrypted under the
     * new version, and the one stored before still decrypts: the flow through
     * the connection still completes.
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
     * A ciphertext the service did not issue is refused with a
     * `RuntimeException` that carries no part of it, never an empty or wrong
     * value.
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
     * Switching an existing installation to the service without re-encrypting
     * what is stored: the client secret stored under `APP_KEY` is one the
     * service cannot decrypt, so the flow's completion is a server error, a
     * `RuntimeException`, never a failed sign-in.
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
     * The configuration check only resolves the application's encrypter: it
     * reports `[secrets]` as working without one request to the service.
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
     * The application's comparisons: the secret and both digests match the
     * value they were made from, and none matches another value.
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
     * A digest by an algorithm that is not a cryptographic hash PHP supports is
     * refused with an `InvalidArgumentException`, naming the algorithm.
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
     * Run the comparisons of the given secret and value against the known
     * secret and the digests of the presented value, and answer whether each
     * matched.
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
     * Register the application's service provider after the package's, and
     * begin a new request, as the first one after the application deploys its
     * binding does: nothing scoped to an earlier request is kept, so nothing
     * resolved under the default encrypter is used again. The harness's fakes
     * are bound again for the new request.
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
