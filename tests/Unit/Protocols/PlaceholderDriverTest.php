<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use Carbon\CarbonImmutable;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Protocols\ConsumedRequest;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\PlaceholderDriver;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\Fixtures\Protocols\ExampleSettings;

/**
 * Unit tests for the package's drivers before their flows land: each fails
 * every flow closed (never complete, every start and completion refused with
 * `connection_unavailable`, nothing described), and reads its protocol's
 * settings through the settings class it names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PlaceholderDriver::class)]
#[CoversClass(OidcDriver::class)]
final class PlaceholderDriverTest extends TestCase
{
    /**
     * Rows of `[driver, name]`: the package's drivers still to be built, by
     * name.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Contracts\ProtocolDriver, 1: string}>
     */
    public static function provideDrivers(): iterable
    {
        yield from [
            'oidc' => [new OidcDriver, 'oidc'],
        ];
    }

    /**
     * No connection is complete, however complete its settings, every flow is
     * refused with `connection_unavailable`, and no response is correlated with
     * a request.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\ProtocolDriver  $driver
     * @param  string  $name
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[DataProvider('provideDrivers')]
    public function testFailsEveryFlowClosed(ProtocolDriver $driver, string $name): void
    {
        $connection  = new ExampleConnection($name, ['issuer' => 'https://idp.example.com']);
        $reference   = RequestReference::generate();
        $start       = $driver->start($connection, new StartRequest(Purpose::SIGN_IN, 'web', $reference, new Secret('state')));
        $response    = CompletionRequest::fromRequest(Request::create('https://api.example.com/callback?code=a&state=b'));
        $correlation = $driver->correlate($connection, $response);
        $completion  = $driver->complete($connection, $response, new ConsumedRequest(Purpose::SIGN_IN, 'web', $reference, CarbonImmutable::now()));
        $describe    = $driver->describe($connection);

        self::assertFalse($driver->isComplete($connection));
        self::assertTrue($start->isRefused());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $start->reason);
        self::assertTrue($correlation->isUncorrelated());
        self::assertTrue($completion->isRefused());
        self::assertFalse($completion->isVerified());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $completion->reason);
        self::assertFalse($describe->isAvailable());
        self::assertSame(FailureReason::CONNECTION_UNAVAILABLE, $describe->reason);
    }

    /**
     * The OIDC driver is registered under its name.
     *
     * @return void
     */
    public function testTheDriversName(): void
    {
        self::assertSame('oidc', OidcDriver::NAME);
    }

    /**
     * The settings are read through the settings class the driver names.
     *
     * @return void
     */
    public function testReadsSettingsThroughItsSettingsClass(): void
    {
        $driver = new class extends PlaceholderDriver {
            /**
             * The example settings.
             *
             * @return string
             */
            #[\Override]
            protected function settingsClass(): string
            {
                return ExampleSettings::class;
            }
        };

        $settings = $driver->settings(['issuer' => 'https://idp.example.com']);

        self::assertInstanceOf(ExampleSettings::class, $settings);
        self::assertSame(['issuer' => 'https://idp.example.com'], $settings->toArray());
    }

    /**
     * A settings class that is not a protocol's settings fails as a
     * misconfiguration, rather than reading settings some other way.
     *
     * @return void
     */
    public function testRefusesASettingsClassThatIsNotProtocolSettings(): void
    {
        $driver = new class extends PlaceholderDriver {
            /**
             * Not a settings class.
             *
             * @return string
             */
            #[\Override]
            protected function settingsClass(): string
            {
                return \stdClass::class;
            }
        };

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('are not available.');

        $driver->settings([]);
    }
}
