<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Config\Checks\ApplicationsCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[applications]` configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationsCheck::class)]
final class ApplicationsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /** @var string A valid redirect URI. */
    private const string REDIRECT = 'https://app.example.com/auth/sso/complete';

    /**
     * Applications are checked only while the package is in use.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.applications', ['web' => []]);

        self::assertNull($this->problemsOf(ApplicationsCheck::class));

        $this->useThePackage();
        config()->set('sso.applications', ['web' => ['redirect_uri' => self::REDIRECT]]);

        self::assertSame([], $this->problemsOf(ApplicationsCheck::class));
    }

    /**
     * Rows of `[applications, problems]`: configurations and their problems.
     *
     * @return iterable<string, array{0: mixed, 1: list<string>}>
     */
    public static function provideConfigurations(): iterable
    {
        $every = [
            'redirect_uri'        => self::REDIRECT,
            'external_sign_in'    => true,
            'delivery'            => 'query',
            'discovery'           => ['enabled' => true, 'fallback_url' => 'https://app.example.com/sign-in'],
            'unlinked_handoffs'   => '1',
            'handoff_ttl_seconds' => '300',
        ];

        $redirect = 'must be an exact redirect URI: an absolute https URL (or http on 127.0.0.1 or [::1]), or a private-use scheme with a dot'
            . ' (`com.example.app:/callback`), with no user information, fragment or wildcard.';

        yield 'none' => [[], []];
        yield 'every setting' => [['web' => $every], []];
        yield 'a native application' => [['mobile' => ['redirect_uri' => 'com.example.app:/sso', 'delivery' => 'fragment']], []];
        yield 'not an array' => ['web', ['`sso.applications` must be an array of applications, by name.']];
        $name = 'Each key of `sso.applications` must be an application name: a lower-case letter, then lower-case letters, digits, `_` and `-`, at most 64 in all.';

        yield 'a list' => [[['redirect_uri' => self::REDIRECT]], [$name]];
        yield 'an upper-case name' => [['Web' => ['redirect_uri' => self::REDIRECT]], [$name]];
        yield 'settings that are not an array' => [['web' => self::REDIRECT], ['`sso.applications.web` must be an array of settings.']];
        yield 'no redirect URI' => [['web' => []], ["`sso.applications.web.redirect_uri` {$redirect}"]];
        yield 'a wildcard redirect URI' => [['web' => ['redirect_uri' => 'https://*.example.com/']], ["`sso.applications.web.redirect_uri` {$redirect}"]];
        yield 'a misspelt setting' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'redirect_url' => self::REDIRECT]],
            ['`sso.applications.web` has no setting [redirect_url]; the settings are redirect_uri, external_sign_in, delivery, discovery, unlinked_handoffs, handoff_ttl_seconds.'],
        ];
        yield 'a malformed switch' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'external_sign_in' => 'yes']],
            ['sso.applications.web.external_sign_in must be true or false.'],
        ];
        yield 'a malformed unlinked switch' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'unlinked_handoffs' => 2]],
            ['sso.applications.web.unlinked_handoffs must be true or false.'],
        ];
        yield 'a handoff living too long' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 301]],
            ['sso.applications.web.handoff_ttl_seconds must be an integer from 1 to 300.'],
        ];
        yield 'a handoff living no time' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'handoff_ttl_seconds' => 0]],
            ['sso.applications.web.handoff_ttl_seconds must be an integer from 1 to 300.'],
        ];
        yield 'an unknown delivery' => [['web' => ['redirect_uri' => self::REDIRECT, 'delivery' => 'body']], ['`sso.applications.web.delivery` must be `fragment` or `query`.']];
        yield 'malformed discovery' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'discovery' => true]],
            ['`sso.applications.web.discovery` must be an array of `enabled` and `fallback_url`.'],
        ];
        yield 'a misspelt discovery setting' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'discovery' => ['on' => true]]],
            ['`sso.applications.web.discovery` must be an array of `enabled` and `fallback_url`.'],
        ];
        yield 'discovery offered with the feature off' => [['web' => ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => true]]], []];
        yield 'a malformed fallback with discovery off' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'discovery' => ['fallback_url' => 'http://app.example.com/']]],
            ["`sso.applications.web.discovery.fallback_url` {$redirect}"],
        ];
        yield 'one problem per application' => [
            ['web' => ['redirect_uri' => self::REDIRECT, 'delivery' => 'body'], 'admin' => [], 'mobile' => ['redirect_uri' => 'com.example.app:/sso']],
            ['`sso.applications.web.delivery` must be `fragment` or `query`.', "`sso.applications.admin.redirect_uri` {$redirect}"],
        ];
    }

    /**
     * Each configuration reports exactly its problems, one per application.
     *
     * @param  mixed  $applications
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideConfigurations')]
    public function testReportsEachProblem(mixed $applications, array $problems): void
    {
        $this->useThePackage();

        config()->set('sso.applications', $applications);

        self::assertSame($problems, $this->problemsOf(ApplicationsCheck::class));
    }

    /**
     * Discovery needs a fallback URL while the feature is on.
     *
     * @return void
     */
    public function testDiscoveryNeedsAFallbackWhileTheFeatureIsOn(): void
    {
        $this->useThePackage();

        config()->set('sso.features.discovery', true);
        config()->set('sso.applications', ['web' => ['redirect_uri' => self::REDIRECT, 'discovery' => ['enabled' => true]]]);

        self::assertSame([
            '`sso.applications.web.discovery.fallback_url` must be an exact redirect URI: an absolute https URL (or http on 127.0.0.1 or [::1]), or a private-use scheme with a dot'
            . ' (`com.example.app:/callback`), with no user information, fragment or wildcard.',
        ], $this->problemsOf(ApplicationsCheck::class));

        config()->set('sso.applications.web.discovery.fallback_url', 'com.example.app:/sign-in');

        self::assertSame([], $this->problemsOf(ApplicationsCheck::class));
    }
}
