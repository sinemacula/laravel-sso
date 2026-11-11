<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Completion\CompletionLocks;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\Enums\LinkingEmailSource;
use SineMacula\Laravel\Sso\Results\LinkingEmail;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for what a completion's transaction locks (`flows.md`): what a
 * consumed completion must hold to lock anything, and exactly when the claim of
 * the linking email's domain is among the locks: a `sign_in` going on, with
 * linking on and an email to look up.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CompletionLocks::class)]
final class CompletionLocksTest extends LinkingTestCase
{
    /** @var string The public reference of the flow a state is built for. */
    private const string REFERENCE = 'Lq8tVv3w0kLmNoPqRsTuVwXyZ0123456';

    /**
     * Rows of `[the part the state does not hold, the message]`.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideMissingParts(): iterable
    {
        yield 'the connection' => ['connection', 'A consumed completion holds its connection.'];
        yield 'the application' => ['application', 'A consumed completion holds its application.'];
        yield 'the request' => ['request', 'A consumed completion holds its request.'];
    }

    /**
     * A completion holding less than it consumed locks nothing, and is a
     * misconfiguration.
     *
     * @param  string  $missing
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMissingParts')]
    public function testACompletionHoldingLessThanItConsumedLocksNothing(string $missing, string $message): void
    {
        $state = $this->signIn();
        $state = $state
            ->withConnection($missing === 'connection' ? null : $state->connection)
            ->withAuthorizationRequest($missing === 'request' ? null : $state->authorizationRequest, $state->consumed, $missing === 'application' ? null : $state->application);

        $this->expectExceptionObject(new \LogicException($message));

        app(CompletionLocks::class)->take($state, true, true);
    }

    /**
     * A `sign_in` going on, with linking on and an email to look up, locks its
     * claim with the connection and the request.
     *
     * @return void
     */
    public function testASignInGoingOnLocksItsClaim(): void
    {
        $state = $this->signIn();
        $lock  = app(CompletionLocks::class)->take($state, true, true);

        self::assertSame($this->domain->id, $lock->domain?->id);
        self::assertSame($this->connection->id, $lock->connection?->id);
        self::assertSame($state->authorizationRequest?->id, $lock->request?->id);
        self::assertNull($lock->enforcement);
    }

    /**
     * A completion not going on, or a continuation that takes no domain, locks
     * no claim.
     *
     * @return void
     */
    public function testOnlyAPreparationGoingOnLocksAClaim(): void
    {
        $state = $this->signIn();

        self::assertNull(app(CompletionLocks::class)->take($state, false, true)->domain);
        self::assertNull(app(CompletionLocks::class)->take($state, true, false)->domain);
    }

    /**
     * A state with no result, or a result with no linking email, looks nothing
     * up.
     *
     * @return void
     */
    public function testNoEmailLooksUpNoClaim(): void
    {
        $state = $this->signIn();

        self::assertNull(app(CompletionLocks::class)->take(self::withoutResult($state), true, true)->domain);
        self::assertNull(app(CompletionLocks::class)->take($state->withResult($this->resultWith(null)), true, true)->domain);
    }

    /**
     * With linking off, or the feature off, an email looks nothing up.
     *
     * @return void
     */
    public function testLinkingOffLooksUpNoClaim(): void
    {
        $state = $this->signIn();

        config()->set('sso.features.domain_linking', false);

        self::assertNull(app(CompletionLocks::class)->take($state, true, true)->domain);

        config()->set('sso.features.domain_linking', true);

        $this->connection->forceFill(['linking_enabled' => false])->save();

        self::assertNull(app(CompletionLocks::class)->take($state, true, true)->domain);
    }

    /**
     * A flow of another purpose, or a state with no consumed request, looks
     * nothing up.
     *
     * @return void
     */
    public function testOnlyASignInLooksUpAClaim(): void
    {
        $state = $this->signIn();
        $link  = new ConsumedRequest(Purpose::LINK, 'web', RequestReference::fromString(self::REFERENCE), $this->clock->now());

        self::assertNull(app(CompletionLocks::class)->take($state->withAuthorizationRequest($state->authorizationRequest, $link, $state->application), true, true)->domain);
        self::assertNull(app(CompletionLocks::class)->take($state->withAuthorizationRequest($state->authorizationRequest, null, $state->application), true, true)->domain);
    }

    /**
     * A connection gone under its lock looks nothing up.
     *
     * @return void
     */
    public function testAConnectionGoneLooksUpNoClaim(): void
    {
        $state = $this->signIn();

        Connection::query()->whereKey($this->connection->id)->delete();

        $lock = app(CompletionLocks::class)->take($state, true, true);

        self::assertNull($lock->connection);
        self::assertNull($lock->domain);
    }

    /**
     * The state as it was before its response was validated.
     *
     * @param  \SineMacula\Laravel\Sso\Completion\CompletionState  $state
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private static function withoutResult(CompletionState $state): CompletionState
    {
        return CompletionState::arrived($state->connectionId, $state->request, Clients::browser())
            ->withConnection($state->connection)
            ->withAuthorizationRequest($state->authorizationRequest, $state->consumed, $state->application);
    }

    /**
     * The state of a `sign_in` whose linking email the claim covers.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private function signIn(): CompletionState
    {
        $this->start();

        $consumed    = new ConsumedRequest(Purpose::SIGN_IN, 'web', RequestReference::fromString(self::REFERENCE), $this->clock->now());
        $application = Application::fromSettings(config(), 'web', ['redirect_uri' => 'https://app.example.com/sso']);

        return CompletionState::arrived($this->connection->id, new CompletionRequest('GET', '', []), Clients::browser())
            ->withConnection($this->connection)
            ->withAuthorizationRequest(AuthorizationRequest::query()->sole(), $consumed, $application)
            ->withResult($this->resultWith(new LinkingEmail(self::EMAIL, LinkingEmailSource::ID_TOKEN)));
    }

    /**
     * A result of the state's flow with the linking email given.
     *
     * @param  ?\SineMacula\Laravel\Sso\Results\LinkingEmail  $email
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     */
    private function resultWith(?LinkingEmail $email): VerifiedResult
    {
        return new VerifiedResult(
            issuer: VerifyingDriver::ISSUER,
            subject: VerifyingDriver::SUBJECT,
            nameIdFormat: null,
            connectionId: $this->connection->id,
            tenantId: 'tenant-1',
            protocol: VerifyingDriver::NAME,
            application: 'web',
            purpose: Purpose::SIGN_IN,
            requestReference: RequestReference::fromString(self::REFERENCE),
            attributes: [],
            emailDomainVerified: false,
            authenticationContext: new AuthenticationContext($this->clock->now()),
            linkingEmail: $email,
        );
    }
}
