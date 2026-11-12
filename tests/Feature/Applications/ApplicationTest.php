<?php

declare(strict_types = 1);

namespace Tests\Feature\Applications;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Applications\Application;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use Tests\TestCase;

/**
 * Feature tests for one registered application's settings.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Application::class)]
final class ApplicationTest extends TestCase
{
    /** @var string A valid redirect URI. */
    private const string REDIRECT = 'https://app.example.com/auth/sso/complete';

    /** @var string What a redirect URI must be. */
    private const string REDIRECT_RULE = 'must be an exact redirect URI: an absolute https URL (or http on 127.0.0.1 or [::1]), or a private-use scheme with a'
        . ' dot (`com.example.app:/callback`), with no user information, fragment or wildcard.';

    /**
     * Every setting is read as configured, the redirect URI exactly.
     *
     * @return void
     */
    public function testReadsEverySetting(): void
    {
        config()->set('sso.features.discovery', true);

        $application = Application::fromSettings(config(), 'mobile', [
            'redirect_uri'        => 'com.example.app:/sso?x=1',
            'external_sign_in'    => '1',
            'delivery'            => 'query',
            'discovery'           => ['enabled' => 'true', 'fallback_url' => 'com.example.app:/sign-in'],
            'unlinked_handoffs'   => 1,
            'handoff_ttl_seconds' => '300',
        ]);

        self::assertSame('mobile', $application->name);
        self::assertSame('com.example.app:/sso?x=1', $application->redirectUri);
        self::assertTrue($application->externalSignIn);
        self::assertSame(HandoffDelivery::QUERY, $application->delivery);
        self::assertTrue($application->discoveryEnabled);
        self::assertSame('com.example.app:/sign-in', $application->discoveryFallbackUrl);
        self::assertTrue($application->unlinkedHandoffs);
        self::assertSame(300, $application->handoffTtlSeconds);
    }

    /**
     * With only its redirect URI, an application allows nothing and takes every
     * default.
     *
     * @return void
     */
    public function testTakesEveryDefault(): void
    {
        $application = Application::fromSettings(config(), 'web', ['redirect_uri' => self::REDIRECT]);

        self::assertSame('web', $application->name);
        self::assertSame(self::REDIRECT, $application->redirectUri);
        self::assertFalse($application->externalSignIn);
        self::assertSame(HandoffDelivery::FRAGMENT, $application->delivery);
        self::assertFalse($application->discoveryEnabled);
        self::assertNull($application->discoveryFallbackUrl);
        self::assertFalse($application->unlinkedHandoffs);
        self::assertSame(60, $application->handoffTtlSeconds);
        self::assertSame(60, Application::HANDOFF_TTL_SECONDS);
        self::assertSame(300, Application::MAX_HANDOFF_TTL_SECONDS);
        self::assertSame(['redirect_uri', 'external_sign_in', 'delivery', 'discovery', 'unlinked_handoffs', 'handoff_ttl_seconds'], Application::SETTINGS);
    }

    /**
     * A handoff lives from one second to five minutes.
     *
     * @return void
     */
    public function testAHandoffLivesOneSecondToFiveMinutes(): void
    {
        self::assertSame(1, Application::fromSettings(config(), 'web', ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 1])->handoffTtlSeconds);
        self::assertSame(299, Application::fromSettings(config(), 'web', ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 299])->handoffTtlSeconds);
    }

    /**
     * A fallback URL is kept whenever given and required only while discovery
     * runs.
     *
     * @return void
     */
    public function testTheFallbackIsRequiredOnlyWhileDiscoveryRuns(): void
    {
        $offered = ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => true]];

        self::assertNull(Application::fromSettings(config(), 'web', $offered)->discoveryFallbackUrl);
        self::assertSame('https://app.example.com/sign-in', Application::fromSettings(config(), 'web', [
            'redirect_uri' => self::REDIRECT,
            'discovery'    => ['fallback_url' => 'https://app.example.com/sign-in'],
        ])->discoveryFallbackUrl);

        config()->set('sso.features.discovery', true);

        self::assertNull(Application::fromSettings(config(), 'web', ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => false]])->discoveryFallbackUrl);

        $this->expectExceptionObject(new \InvalidArgumentException('`sso.applications.web.discovery.fallback_url` ' . self::REDIRECT_RULE));

        Application::fromSettings(config(), 'web', $offered);
    }

    /**
     * The `discovery` feature is read from the repository given.
     *
     * @return void
     */
    public function testTheDiscoveryFeatureIsReadFromTheRepositoryGiven(): void
    {
        $offered = ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => true]];

        self::assertNull(Application::fromSettings(config(), 'web', $offered)->discoveryFallbackUrl);

        $this->expectExceptionObject(new \InvalidArgumentException('`sso.applications.web.discovery.fallback_url` ' . self::REDIRECT_RULE));

        Application::fromSettings(new Repository(['sso' => ['features' => ['discovery' => true]]]), 'web', $offered);
    }

    /**
     * Rows of `[name, settings, message]`: malformed applications and their
     * messages.
     *
     * @return iterable<string, array{0: string, 1: mixed, 2: string}>
     */
    public static function provideMalformedApplications(): iterable
    {
        $name = 'Each key of `sso.applications` must be an application name: a lower-case letter, then lower-case letters, digits, `_` and `-`, at most 64 in all.';

        yield 'an upper-case name' => ['Web', ['redirect_uri' => self::REDIRECT], $name];
        yield 'a name starting with a digit' => ['1web', ['redirect_uri' => self::REDIRECT], $name];
        yield 'a name of 65 characters' => ['w' . str_repeat('a', 64), ['redirect_uri' => self::REDIRECT], $name];
        yield 'a name ending in a newline' => ["web\n", ['redirect_uri' => self::REDIRECT], $name];
        yield 'settings that are not an array' => ['web', self::REDIRECT, '`sso.applications.web` must be an array of settings.'];
        yield 'no redirect URI' => ['web', [], '`sso.applications.web.redirect_uri` ' . self::REDIRECT_RULE];
        yield 'a misspelt setting' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'return_url' => self::REDIRECT],
            '`sso.applications.web` has no setting [return_url]; the settings are redirect_uri, external_sign_in, delivery, discovery, unlinked_handoffs, handoff_ttl_seconds.',
        ];
        yield 'a malformed switch' => ['web', ['redirect_uri' => self::REDIRECT, 'external_sign_in' => 'yes'], 'sso.applications.web.external_sign_in must be true or false.'];
        yield 'a malformed unlinked switch' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'unlinked_handoffs' => 2],
            'sso.applications.web.unlinked_handoffs must be true or false.',
        ];
        yield 'a handoff living no time' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 0],
            'sso.applications.web.handoff_ttl_seconds must be an integer from 1 to 300.',
        ];
        yield 'a handoff living too long' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 301],
            'sso.applications.web.handoff_ttl_seconds must be an integer from 1 to 300.',
        ];
        yield 'an unknown delivery' => ['web', ['redirect_uri' => self::REDIRECT, 'delivery' => 'body'], '`sso.applications.web.delivery` must be `fragment` or `query`.'];
        yield 'a delivery that is not a string' => ['web', ['redirect_uri' => self::REDIRECT, 'delivery' => 1], '`sso.applications.web.delivery` must be `fragment` or `query`.'];
        yield 'malformed discovery' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'discovery' => true],
            '`sso.applications.web.discovery` must be an array of `enabled` and `fallback_url`.',
        ];
        yield 'a misspelt discovery setting' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => true, 'fallback' => self::REDIRECT]],
            '`sso.applications.web.discovery` must be an array of `enabled` and `fallback_url`.',
        ];
        yield 'a malformed discovery switch' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => 'on']],
            'sso.applications.web.discovery.enabled must be true or false.',
        ];
        yield 'a malformed fallback' => [
            'web',
            ['redirect_uri' => self::REDIRECT, 'discovery' => ['fallback_url' => 'https://*.example.com/']],
            '`sso.applications.web.discovery.fallback_url` ' . self::REDIRECT_RULE,
        ];
    }

    /**
     * Each malformed application fails with its message.
     *
     * @param  string  $name
     * @param  mixed  $settings
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformedApplications')]
    public function testRefusesAMalformedApplication(string $name, mixed $settings, string $message): void
    {
        $this->expectExceptionObject(new \InvalidArgumentException($message));

        Application::fromSettings(config(), $name, $settings);
    }

    /**
     * A name is a lower-case letter then up to 63 of `a-z`, `0-9`, `_` and `-`.
     *
     * @return void
     */
    public function testWhatAnApplicationNameIs(): void
    {
        self::assertTrue(Application::isName('a'));
        self::assertTrue(Application::isName('web_app-2'));
        self::assertTrue(Application::isName('w' . str_repeat('a', 63)));
        self::assertFalse(Application::isName('w' . str_repeat('a', 64)));
        self::assertFalse(Application::isName(''));
        self::assertFalse(Application::isName('_web'));
        self::assertFalse(Application::isName('web.x'));
        self::assertFalse(Application::isName("web\n"));
    }
}
