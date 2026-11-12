<?php

declare(strict_types = 1);

namespace Tests\Feature\Config\Checks;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Config\Checks\FeaturesCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for the `[features]` configuration check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FeaturesCheck::class)]
final class FeaturesCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * The defaults pass, and the switches are always checked.
     *
     * @return void
     */
    public function testTheDefaultsPassAndAreAlwaysChecked(): void
    {
        self::assertSame([], $this->problemsOf(FeaturesCheck::class));
    }

    /**
     * Rows of `[settings, problems]`: switch configurations and their problems.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideConfigurations(): iterable
    {
        yield 'a protocol alone' => [['sso.features.oidc' => true], []];
        yield 'every feature with saml2' => [[
            'sso.features' => [
                'saml2'            => true, 'discovery' => true, 'enforcement' => true, 'encrypted_assertions' => true,
                'metadata_refresh' => true, 'idp_initiated' => true, 'domain_linking' => true,
            ],
        ], []];
        yield 'a malformed switch' => [['sso.features.discovery' => 'yes'], ['sso.features.discovery must be true or false.']];
        yield 'a block that is not an array' => [['sso.features' => true], ['`sso.features` must be an array of switches.']];
        yield 'a misspelt switch' => [
            ['sso.features.saml' => true],
            ['`sso.features` has no switch [saml]; the switches are saml2, oidc, discovery, enforcement, encrypted_assertions, metadata_refresh, idp_initiated, domain_linking.'],
        ];
        yield 'a feature with no protocol' => [
            ['sso.features.discovery' => true],
            ['`sso.features.discovery` is on, but it needs `sso.features.saml2` or `sso.features.oidc` on as well.'],
        ];
        yield 'a SAML feature over OIDC' => [
            ['sso.features.oidc' => true, 'sso.features.idp_initiated' => true, 'sso.features.encrypted_assertions' => '1'],
            [
                '`sso.features.encrypted_assertions` is on, but it needs `sso.features.saml2` on as well.',
                '`sso.features.idp_initiated` is on, but it needs `sso.features.saml2` on as well.',
            ],
        ];
        yield 'a feature over a malformed protocol' => [
            ['sso.features.saml2' => 'on', 'sso.features.enforcement' => true],
            [
                'sso.features.saml2 must be true or false.',
                '`sso.features.enforcement` is on, but it needs `sso.features.saml2` or `sso.features.oidc` on as well.',
            ],
        ];
    }

    /**
     * Each configuration reports exactly its problems, every one in a run.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideConfigurations')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        config()->set($settings);

        self::assertSame($problems, $this->problemsOf(FeaturesCheck::class));
    }
}
