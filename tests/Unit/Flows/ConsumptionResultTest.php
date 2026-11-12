<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\ConsumptionResult;
use SineMacula\Laravel\Sso\Flows\Enums\ConsumptionStatus;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;
use Tests\TestCase;

/**
 * Unit tests for authorisation request consumption results.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConsumptionResult::class)]
#[CoversClass(ConsumptionStatus::class)]
final class ConsumptionResultTest extends TestCase
{
    /** @var string The request's public reference. */
    private const string REFERENCE = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

    /** @var string The PKCE verifier the consumed request holds. */
    private const string PKCE_VERIFIER = 'the-pkce-verifier-of-the-request-0123456789';

    /**
     * The statuses and their stable values.
     *
     * @return void
     */
    public function testTheStatusesAreStable(): void
    {
        self::assertSame(['consumed', 'refused', 'unknown', 'replayed'], array_map(static fn (ConsumptionStatus $status): string => $status->value, ConsumptionStatus::cases()));
    }

    /**
     * A consumed request carries the request, the driver's view and the app.
     *
     * @return void
     */
    public function testAConsumedRequestCarriesTheRequestTheConsumedRequestAndTheApplication(): void
    {
        $request     = self::request();
        $consumed    = self::consumedRequest();
        $application = self::application();

        $result = ConsumptionResult::consumed($request, $consumed, $application);

        self::assertSame(ConsumptionStatus::CONSUMED, $result->status);
        self::assertSame($request, $result->request);
        self::assertSame($consumed, $result->consumed);
        self::assertSame($application, $result->application);
        self::assertNull($result->reason);
        self::assertSame([true, false, false, false, true], self::predicates($result));
    }

    /**
     * A refused request carries the reason and any still-registered app.
     *
     * @return void
     */
    public function testARefusedRequestCarriesTheReasonAndTheApplicationWhenThereIsOne(): void
    {
        $request     = self::request();
        $application = self::application();

        $redirectable = ConsumptionResult::refused(FailureReason::REQUEST_EXPIRED, $request, $application);

        self::assertSame(ConsumptionStatus::REFUSED, $redirectable->status);
        self::assertSame($request, $redirectable->request);
        self::assertNull($redirectable->consumed);
        self::assertSame($application, $redirectable->application);
        self::assertSame(FailureReason::REQUEST_EXPIRED, $redirectable->reason);
        self::assertSame([false, true, false, false, true], self::predicates($redirectable));

        $stranded = ConsumptionResult::refused(FailureReason::APPLICATION_NOT_ALLOWED, $request);

        self::assertSame(ConsumptionStatus::REFUSED, $stranded->status);
        self::assertSame($request, $stranded->request);
        self::assertNull($stranded->consumed);
        self::assertNull($stranded->application);
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $stranded->reason);
        self::assertSame([false, true, false, false, false], self::predicates($stranded));
    }

    /**
     * An unknown request carries nothing but `request_unknown`.
     *
     * @return void
     */
    public function testAnUnknownRequestCarriesNothingButItsReason(): void
    {
        $result = ConsumptionResult::unknown();

        self::assertSame(ConsumptionStatus::UNKNOWN, $result->status);
        self::assertNull($result->request);
        self::assertNull($result->consumed);
        self::assertNull($result->application);
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
        self::assertSame([false, false, true, false, false], self::predicates($result));
    }

    /**
     * A replayed request carries `request_unknown` and no redirect target.
     *
     * @return void
     */
    public function testAReplayedRequestCarriesTheRequestAndNoRedirectTarget(): void
    {
        $request = self::request();

        $result = ConsumptionResult::replayed($request);

        self::assertSame(ConsumptionStatus::REPLAYED, $result->status);
        self::assertSame($request, $result->request);
        self::assertNull($result->consumed);
        self::assertNull($result->application);
        self::assertSame(FailureReason::REQUEST_UNKNOWN, $result->reason);
        self::assertSame([false, false, false, true, false], self::predicates($result));
    }

    /**
     * No dump shows a column, a digest or the PKCE verifier.
     *
     * @return void
     */
    public function testADumpShowsNoColumnOrSecret(): void
    {
        $consumed = ConsumptionResult::consumed(self::request(), self::consumedRequest(), self::application());

        self::assertSame(['status' => 'consumed', 'request_reference' => self::REFERENCE, 'application' => 'web', 'reason' => null], $consumed->__debugInfo());

        $unknown = ConsumptionResult::unknown();

        self::assertSame(['status' => 'unknown', 'request_reference' => null, 'application' => null, 'reason' => 'request_unknown'], $unknown->__debugInfo());

        $dumped  = (string) (new CliDumper)->dump((new VarCloner)->cloneVar($consumed), true);
        $printed = print_r($consumed, true);

        self::assertStringNotContainsString(self::PKCE_VERIFIER, $dumped);

        foreach ([self::PKCE_VERIFIER, str_repeat('d', 64), 'the-ciphertext'] as $hidden) {
            self::assertStringNotContainsString($hidden, $printed);
        }
    }

    /**
     * The result refuses to be serialised.
     *
     * @return void
     */
    public function testTheResultRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A consumption result cannot be serialised.');

        serialize(ConsumptionResult::unknown());
    }

    /**
     * The result refuses to be unserialised.
     *
     * @return void
     */
    public function testTheResultRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A consumption result cannot be unserialised.');

        unserialize('O:' . strlen(ConsumptionResult::class) . ':"' . ConsumptionResult::class . '":0:{}');
    }

    /**
     * The predicates in order, then whether there is a redirect target.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\ConsumptionResult  $result
     * @return list<bool>
     */
    private static function predicates(ConsumptionResult $result): array
    {
        return [$result->isConsumed(), $result->isRefused(), $result->isUnknown(), $result->isReplayed(), $result->hasRedirectTarget()];
    }

    /**
     * An in-memory request with digests and an encrypted verifier.
     *
     * @return \SineMacula\Laravel\Sso\Models\AuthorizationRequest
     */
    private static function request(): AuthorizationRequest
    {
        $request = new AuthorizationRequest;

        $request->forceFill([
            'id'                => '01jbz0000000000000000000aa',
            'reference'         => self::REFERENCE,
            'state_digest'      => str_repeat('d', 64),
            'purpose'           => Purpose::SIGN_IN,
            'application'       => 'web',
            'connection_id'     => '01jbz0000000000000000000cc',
            'nonce_digest'      => str_repeat('e', 64),
            'code_verifier'     => 'the-ciphertext',
            'handoff_challenge' => str_repeat('c', 43),
        ]);

        return $request;
    }

    /**
     * What the driver is given of the request.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ConsumedRequest
     */
    private static function consumedRequest(): ConsumedRequest
    {
        return new ConsumedRequest(
            purpose: Purpose::SIGN_IN,
            application: 'web',
            reference: RequestReference::fromString(self::REFERENCE),
            startedAt: CarbonImmutable::parse('2026-11-01T09:30:00Z'),
            nonceDigest: str_repeat('e', 64),
            codeVerifier: app(SecretEncrypter::class)->encrypt(self::PKCE_VERIFIER),
            encrypter: app(SecretEncrypter::class),
        );
    }

    /**
     * The registered `web` application.
     *
     * @return \SineMacula\Laravel\Sso\Applications\Application
     */
    private static function application(): Application
    {
        return Application::fromSettings(config(), 'web', ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true]);
    }
}
