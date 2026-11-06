<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Readme;

use Illuminate\Console\Application as Artisan;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Foundation\Configuration\ApplicationBuilder;
use Illuminate\Support\Str;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\ApplicationGate;
use SineMacula\Laravel\Sso\Completion\CompletionService;
use SineMacula\Laravel\Sso\Completion\Enums\CompletionEndpoint;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Operations\OperationsSchedule;
use SineMacula\Laravel\Sso\Responses\CompletionResponses;
use SineMacula\Laravel\Sso\Testing\FakeSamlIdentityProvider;
use SineMacula\Laravel\Sso\Testing\HandoffRedirect;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\ExampleTestCase;

/**
 * The README's configuration and wiring (SSO-12.5), run on the shared example
 * harness: the application its published `config/sso.php` registers receives
 * the handoff on exactly its redirect URI, and one it does not register, or
 * registers without external sign-in, is refused; the schedule its
 * `bootstrap/app.php` wires runs the package's operations once Artisan starts,
 * and nothing while no protocol is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Application::class)]
#[CoversClass(ApplicationGate::class)]
#[CoversClass(OperationsSchedule::class)]
final class ReadmeExampleTest extends ExampleTestCase
{
    /** @var string The redirect URI the README registers. */
    private const string README_REDIRECT_URI = 'https://app.example.com/auth/sso/complete';

    /**
     * The README's application signs in through a linked SAML connection, and
     * the browser is sent back to exactly its redirect URI, with a code the
     * application admits.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheReadmesApplicationReceivesTheHandoffOnItsRedirectUri(): void
    {
        $this->publishConfiguration();

        $idp          = new FakeSamlIdentityProvider;
        $connectionId = $this->makeSamlConnection($idp);
        $person       = new IdentityReference('App\Models\User', 'person-1');

        $this->linkThroughFlow($idp, $connectionId, $person);

        $start    = $this->startFlow(Purpose::SIGN_IN, $connectionId);
        $request  = $idp->receive($start);
        $response = $idp->respondTo($request, $this->clock->now());
        $result   = app(CompletionService::class)->complete(
            CompletionEndpoint::ASSERTION_CONSUMER_SERVICE,
            $connectionId,
            $response->completionRequest($request->relayState),
            Clients::browser(),
        );
        $location = app(CompletionResponses::class)->from($result, 'POST')->location();

        self::assertNotNull($location);
        self::assertSame(self::README_REDIRECT_URI, Str::before($location, '#'));

        $redirect = HandoffRedirect::from($location);

        self::assertSame($start->reference?->value, $redirect->reference);

        $signedIn = $this->admitSignIn($connectionId, $redirect, $start, 'session-1');

        self::assertTrue($signedIn->isAdmitted());
        self::assertEquals($person, $signedIn->linkedIdentity);
    }

    /**
     * An application the configuration does not register, and one it registers
     * without `external_sign_in`, never start a flow.
     *
     * @return void
     */
    public function testAnApplicationTheConfigurationDoesNotAllowIsRefused(): void
    {
        $this->publishConfiguration();

        config()->set('sso.applications.admin', ['redirect_uri' => 'https://admin.example.com/auth/sso/complete']);

        $connectionId = $this->makeSamlConnection(new FakeSamlIdentityProvider);

        foreach (['mobile', 'admin'] as $application) {

            $refused = app(AuthorizationRequestService::class)->start($application, Purpose::SIGN_IN, $connectionId, Clients::browser());

            self::assertTrue($refused->isRefused(), $application);
            self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $refused->reason, $application);
        }

        self::assertTrue($this->startFlow(Purpose::SIGN_IN, $connectionId)->isStarted());
    }

    /**
     * Once Artisan starts, the schedule the README wires holds each of the
     * package's operations on its default cadence.
     *
     * @return void
     */
    public function testTheReadmesScheduleRunsThePackagesOperations(): void
    {
        self::assertSame([
            'sso:prune'            => '0 * * * *',
            'sso:domains:recheck'  => '0 * * * *',
            'sso:metadata:refresh' => '*/5 * * * *',
            'sso:keys:expiring'    => '0 0 * * *',
        ], $this->scheduledOnStarting());
    }

    /**
     * While no protocol is on, the schedule the README wires holds none of the
     * package's operations, since the tables they read may not exist.
     *
     * @return void
     */
    public function testTheReadmesScheduleHoldsNothingWhileNoProtocolIsOn(): void
    {
        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', false);

        self::assertSame([], $this->scheduledOnStarting());
    }

    /**
     * Lay the README's published configuration over the package's, key by key,
     * as Laravel merges a published file with a package's.
     *
     * @return void
     */
    private function publishConfiguration(): void
    {
        /** @var array<string, mixed> $published */
        $published = require __DIR__ . '/config/sso.php';

        /** @var array<string, mixed> $package */
        $package = config('sso');

        config()->set('sso', array_replace($package, $published));
    }

    /**
     * Configure the application under test with the README's
     * `bootstrap/app.php`, start Artisan as `php artisan` does, and answer the
     * package's operations the schedule then holds, each command's cadence by
     * the command.
     *
     * @return array<string, string>
     */
    private function scheduledOnStarting(): array
    {
        /** @var \Closure(\Illuminate\Foundation\Configuration\ApplicationBuilder): \Illuminate\Foundation\Application $bootstrap */
        $bootstrap = require __DIR__ . '/bootstrap/app.php';

        $application = app();

        $bootstrap(new ApplicationBuilder($application));

        // Starting a console application runs what the builder wired to it
        new Artisan($application, $application->make(Dispatcher::class), $application->version());

        $scheduled = [];

        foreach ($application->make(Schedule::class)->events() as $event) {

            $command = Str::afterLast((string) $event->command, ' ');

            if (!in_array($command, OperationsSchedule::COMMANDS, true)) {
                continue;
            }

            $scheduled[$command] = $event->expression;
        }

        return $scheduled;
    }
}
