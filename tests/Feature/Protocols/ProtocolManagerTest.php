<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Container\Container;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Foundation\Application as FoundationApplication;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\ProtocolDriver;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Protocols\Oidc\OidcDriver;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Driver;
use Tests\Fixtures\Protocols\ExampleDriver;
use Tests\TestCase;

/**
 * Feature tests for the protocol registry (SSO-2.2): the container binding, the
 * package's own drivers, drivers registered with `extend()`, the refusals for a
 * driver that is unknown, reserved, misnamed or not a driver, building drivers
 * with the application serving, when a protocol is available and a connection
 * usable (SSO-2.1), and the presets.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProtocolManager::class)]
final class ProtocolManagerTest extends TestCase
{
    /**
     * The registry is a container singleton that builds each package driver
     * once, and names the package's drivers first.
     *
     * @return void
     */
    public function testIsASingletonThatBuildsThePackageDriversOnce(): void
    {
        $manager = $this->manager();

        self::assertSame($manager, $this->manager());
        self::assertSame(['saml2', 'oidc'], $manager->names());

        $saml = $manager->protocol('saml2');
        $oidc = $manager->protocol('oidc');

        self::assertInstanceOf(Saml2Driver::class, $saml);
        self::assertInstanceOf(OidcDriver::class, $oidc);
        self::assertSame($saml, $manager->protocol('saml2'));
        self::assertSame($oidc, $manager->protocol('oidc'));
    }

    /**
     * A driver registered with `extend()` is built from the container under its
     * name, and named after the package's own, in the order registered.
     *
     * @return void
     */
    public function testExtendRegistersADriverUnderItsName(): void
    {
        $driver   = new ExampleDriver;
        $received = null;

        $returned = $this->manager()->extend('example', function (Application $app) use ($driver, &$received): ProtocolDriver {
            $received = $app;

            return $driver;
        });

        $this->manager()->extend('another', fn (): ProtocolDriver => new ExampleDriver);

        self::assertSame($this->manager(), $returned);
        self::assertSame($driver, $this->manager()->protocol('example'));
        self::assertSame($this->app, $received);
        self::assertTrue($this->manager()->isRegistered('example'));
        self::assertSame(['saml2', 'oidc', 'example', 'another'], $this->manager()->names());
    }

    /**
     * Rows of `[name]`: the package's own drivers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function providePackageDrivers(): iterable
    {
        yield from [
            'saml2' => ['saml2'],
            'oidc'  => ['oidc'],
        ];
    }

    /**
     * The package's own drivers cannot be replaced, and still resolve to the
     * package's own.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('providePackageDrivers')]
    public function testThePackageDriversAreReserved(string $name): void
    {
        $manager = $this->manager();

        try {
            $manager->extend($name, fn (): ProtocolDriver => new ExampleDriver);
            self::fail("Expected [{$name}] to be reserved.");
        } catch (\InvalidArgumentException $exception) {
            self::assertSame("The [{$name}] protocol is the package's own and cannot be replaced; register yours under another name.", $exception->getMessage());
        }

        self::assertNotInstanceOf(ExampleDriver::class, $manager->protocol($name));
    }

    /**
     * Rows of `[name]` that are not a lower-case driver name.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideMalformedNames(): iterable
    {
        yield from [
            'title case'       => ['Example'],
            'upper case'       => ['CAS'],
            'hyphenated'       => ['ws-fed'],
            'leading digit'    => ['2saml'],
            'leading score'    => ['_cas'],
            'trailing newline' => ["cas\n"],
            'spaced'           => ['ws fed'],
            'empty'            => [''],
            'too long'         => [str_repeat('a', 65)],
            'not a string'     => [5],
        ];
    }

    /**
     * A driver is registered only under a lower-case name of up to 64
     * characters, so each protocol has one spelling a connection can hold.
     *
     * @param  mixed  $name
     * @return void
     */
    #[DataProvider('provideMalformedNames')]
    public function testExtendRefusesANameThatIsNotLowerCase(mixed $name): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A protocol driver\'s name must be lower case: a letter, then up to 63 letters, digits or underscores.');

        $this->manager()->extend($name, fn (): ProtocolDriver => new ExampleDriver);
    }

    /**
     * The name check accepts exactly the names a driver can be registered
     * under.
     *
     * @return void
     */
    public function testIsValidNameAcceptsOnlyRegistrableNames(): void
    {
        foreach (['saml2', 'oidc', 'ws_fed', 'cas3', str_repeat('a', 64)] as $name) {
            self::assertTrue(ProtocolManager::isValidName($name), $name);
        }

        foreach (['SAML2', 'ws-fed', '2fa', '_cas', "cas\n", 'ws fed', '', str_repeat('a', 65)] as $name) {
            self::assertFalse(ProtocolManager::isValidName($name), $name);
        }
    }

    /**
     * Rows of `[name]`: names no driver is registered under, spellings of a
     * registered one among them.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideUnknownNames(): iterable
    {
        yield from [
            'unknown'     => ['cas'],
            'upper case'  => ['SAML2'],
            'title case'  => ['Oidc'],
            'hyphenated'  => ['sam-l2'],
            'registered+' => ['EXAMPLE'],
        ];
    }

    /**
     * A driver resolves only by the exact name it was registered under, so a
     * connection cannot name a second spelling of one protocol; `driver()`
     * holds to the same rule as `protocol()`.
     *
     * @param  string  $name
     * @return void
     */
    #[DataProvider('provideUnknownNames')]
    public function testResolvesOnlyTheExactNameADriverWasRegisteredUnder(string $name): void
    {
        $manager = $this->manager();

        $manager->extend('example', fn (): ProtocolDriver => new ExampleDriver);

        self::assertFalse($manager->isRegistered($name));

        foreach ([static fn (): mixed => $manager->protocol($name), static fn (): mixed => $manager->driver($name)] as $resolve) {
            try {
                $resolve();
                self::fail("Expected [{$name}] to be unknown.");
            } catch (\InvalidArgumentException $exception) {
                self::assertSame("Protocol driver [{$name}] is not registered.", $exception->getMessage());
            }
        }
    }

    /**
     * A registered driver that does not implement `ProtocolDriver` fails as a
     * misconfiguration naming the protocol and what it resolved to.
     *
     * @return void
     */
    public function testRejectsADriverThatIsNotAProtocolDriver(): void
    {
        $this->manager()->extend('broken', fn (): \stdClass => new \stdClass);

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('Protocol driver [broken] resolved to stdClass, which does not implement ' . ProtocolDriver::class . '.');

        $this->manager()->protocol('broken');
    }

    /**
     * There is no default driver.
     *
     * @return void
     */
    public function testHasNoDefaultDriver(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Protocol drivers have no default; name the protocol to use.');

        $this->manager()->driver();
    }

    /**
     * A manager resolved by one application builds its drivers with the one now
     * serving, as an Octane sandbox is, and the booted application, serving
     * again, gets drivers of its own once more; a registered driver stays
     * registered throughout.
     *
     * @return void
     */
    public function testBuildsTheDriversWithTheApplicationNowServing(): void
    {
        $app      = $this->booted();
        $manager  = $this->manager();
        $received = [];

        $manager->extend('example', function (Application $app) use (&$received): ProtocolDriver {
            $received[] = $app;

            return new ExampleDriver;
        });

        $booted = $manager->protocol('saml2');

        $manager->protocol('example');

        $sandbox = $this->sandboxOf($app);

        try {
            $served = $manager->protocol('saml2');

            $manager->protocol('example');
            $manager->protocol('example');

            self::assertNotSame($booted, $served);
            self::assertSame($served, $manager->protocol('saml2'));
            self::assertSame($sandbox, $manager->getContainer());
        } finally {
            Container::setInstance($app);
        }

        self::assertNotSame($served, $manager->protocol('saml2'));
        self::assertSame($app, $manager->getContainer());
        self::assertSame([$app, $sandbox], $received);
    }

    /**
     * A manager given a container of its own, at construction or through
     * `setContainer()`, keeps building its drivers with it.
     *
     * @return void
     */
    public function testAManagerGivenItsOwnContainerKeepsIt(): void
    {
        $app      = $this->booted();
        $own      = $this->copyOf($app);
        $received = [];

        $built = new ProtocolManager($own);
        $given = $this->manager()->setContainer($own);

        foreach ([$built, $given] as $manager) {
            $manager->extend('example', function (Application $app) use (&$received): ProtocolDriver {
                $received[] = $app;

                return new ExampleDriver;
            });
        }

        $this->sandboxOf($app);

        try {
            $built->protocol('example');
            $given->protocol('example');
        } finally {
            Container::setInstance($app);
        }

        self::assertSame([$own, $own], $received);
        self::assertSame($own, $built->getContainer());
        self::assertSame($own, $given->getContainer());
    }

    /**
     * A package protocol is available while its feature is on; a registered one
     * while either protocol is; an unregistered one never.
     *
     * @return void
     */
    public function testAProtocolIsAvailableWhileItsFeatureIsOn(): void
    {
        $manager = $this->manager();

        $manager->extend('example', fn (): ProtocolDriver => new ExampleDriver);

        self::assertSame(['saml2' => false, 'oidc' => false, 'example' => false, 'cas' => false], $this->availability($manager));

        config()->set('sso.features.saml2', true);

        self::assertSame(['saml2' => true, 'oidc' => false, 'example' => true, 'cas' => false], $this->availability($manager));

        config()->set('sso.features.saml2', false);
        config()->set('sso.features.oidc', '1');

        self::assertSame(['saml2' => false, 'oidc' => true, 'example' => true, 'cas' => false], $this->availability($manager));
    }

    /**
     * A malformed protocol switch fails closed rather than reading as off or
     * on.
     *
     * @return void
     */
    public function testAMalformedSwitchFailsClosed(): void
    {
        config()->set('sso.features.oidc', 'yes');

        $this->expectException(\InvalidArgumentException::class);

        $this->manager()->isAvailable('oidc');
    }

    /**
     * A connection is usable only while it is enabled, its protocol available
     * and its driver finds it complete; the package's placeholders never do.
     *
     * @return void
     */
    public function testAConnectionIsUsableOnlyWhenEnabledAvailableAndComplete(): void
    {
        $manager = $this->manager();

        $manager->extend('example', fn (): ProtocolDriver => new ExampleDriver);

        $complete   = self::connection('example', true, ['issuer' => 'https://idp.example.com']);
        $incomplete = self::connection('example', true, []);
        $disabled   = self::connection('example', false, ['issuer' => 'https://idp.example.com']);
        $unknown    = self::connection('cas', true, ['issuer' => 'https://idp.example.com']);
        $saml       = self::connection('saml2', true, ['idp_entity_id' => 'https://idp.example.com']);

        self::assertFalse($manager->isUsable($complete), 'A protocol whose feature is off is never usable.');

        config()->set('sso.features.saml2', true);

        self::assertTrue($manager->isUsable($complete));
        self::assertFalse($manager->isUsable($incomplete));
        self::assertFalse($manager->isUsable($disabled));
        self::assertFalse($manager->isUsable($unknown));
        self::assertFalse($manager->isUsable($saml), 'A placeholder is never complete.');
    }

    /**
     * The shipped presets are found by name, an application's registered ones
     * after them; an unknown name finds none.
     *
     * @return void
     */
    public function testFindsThePresets(): void
    {
        $manager = $this->manager();

        $manager->extend('example', fn (): ProtocolDriver => new ExampleDriver);

        $acme = new Preset('acme', 'example', ['issuer' => 'https://idp.acme.example']);

        self::assertSame($manager, $manager->registerPreset($acme));
        self::assertSame($acme, $manager->preset('acme'));
        self::assertSame('google', $manager->preset('google')?->name);
        self::assertNull($manager->preset('nope'));
        self::assertSame(['google', 'microsoft_entra', 'okta', 'auth0', 'microsoft_entra_saml', 'acme'], array_keys($manager->presets()));
    }

    /**
     * A shipped preset cannot be replaced, and a preset's protocol must be
     * registered.
     *
     * @return void
     */
    public function testRefusesAPresetThatReplacesAShippedOneOrHasNoProtocol(): void
    {
        $manager = $this->manager();

        try {
            $manager->registerPreset(new Preset('google', 'oidc'));
            self::fail('A shipped preset was replaced.');
        } catch (\InvalidArgumentException $exception) {
            self::assertSame('The [google] preset is the package\'s own and cannot be replaced; register yours under another name.', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('The [acme] preset is for the [cas] protocol, which is not registered.');

        $manager->registerPreset(new Preset('acme', 'cas'));
    }

    /**
     * Whether each of the four protocols is available.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\ProtocolManager  $manager
     * @return array<string, bool>
     */
    private function availability(ProtocolManager $manager): array
    {
        $available = [];

        foreach (['saml2', 'oidc', 'example', 'cas'] as $name) {
            $available[$name] = $manager->isAvailable($name);
        }

        return $available;
    }

    /**
     * An unsaved connection over the protocol, enabled or not, with the
     * settings given.
     *
     * @param  string  $protocol
     * @param  bool  $enabled
     * @param  array<string, mixed>  $settings
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(string $protocol, bool $enabled, array $settings): Connection
    {
        return (new Connection)->forceFill([
            'id'           => '01jbexampleconnection00000',
            'tenant_id'    => 'tenant-1',
            'protocol'     => $protocol,
            'display_name' => 'Example',
            'settings'     => $settings,
            'enabled'      => $enabled,
        ]);
    }

    /**
     * The test's application, asserted to be the one serving.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function booted(): FoundationApplication
    {
        $app = $this->app;

        self::assertInstanceOf(FoundationApplication::class, $app);
        self::assertSame($app, Container::getInstance());

        return $app;
    }

    /**
     * Make a copy of the application with a configuration of its own, the one
     * serving, as Octane does for a request.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \Illuminate\Foundation\Application
     */
    private function sandboxOf(FoundationApplication $app): FoundationApplication
    {
        $sandbox = $this->copyOf($app);

        Container::setInstance($sandbox);

        return $sandbox;
    }

    /**
     * Make a copy of the application with a configuration of its own.
     *
     * @param  \Illuminate\Foundation\Application  $app
     * @return \Illuminate\Foundation\Application
     */
    private function copyOf(FoundationApplication $app): FoundationApplication
    {
        $copy = clone $app;

        $copy->instance('config', clone $app->make(ConfigRepository::class));

        return $copy;
    }

    /**
     * Resolve the registry from the container.
     *
     * @return \SineMacula\Laravel\Sso\Protocols\ProtocolManager
     */
    private function manager(): ProtocolManager
    {
        return app(ProtocolManager::class);
    }
}
