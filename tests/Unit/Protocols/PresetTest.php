<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Preset;

/**
 * Unit tests for a preset, where what an administrator gives always wins.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Preset::class)]
final class PresetTest extends TestCase
{
    /**
     * What is given replaces what the preset fills in, setting by setting, and
     * a list is replaced whole rather than merged.
     *
     * @return void
     */
    public function testWhatIsGivenReplacesWhatThePresetFillsIn(): void
    {
        $preset = new Preset('acme', 'oidc', ['scopes' => ['openid', 'email'], 'client_authentication' => 'client_secret_basic'], ['email' => 'email', 'display_name' => 'name']);

        self::assertSame(
            ['scopes' => ['openid'], 'client_authentication' => 'client_secret_basic', 'issuer' => 'https://idp.example.com'],
            $preset->fill(['scopes' => ['openid'], 'issuer' => 'https://idp.example.com']),
        );
        self::assertSame(['email' => 'mail', 'display_name' => 'name', 'groups' => 'roles'], $preset->fillMapping(['email' => 'mail', 'groups' => 'roles']));
        self::assertSame($preset->settings, $preset->fill([]));
    }

    /**
     * A preset's OIDC issuer decides over an entity id its settings also hold.
     *
     * @return void
     */
    public function testTheIssuerFilledInDecidesOverAnEntityId(): void
    {
        $both = new Preset('acme', 'oidc', ['issuer' => 'https://issuer.example.com', 'idp_entity_id' => 'https://entity.example.com']);
        $saml = new Preset('acme', 'saml2', ['idp_entity_id' => 'https://entity.example.com']);

        self::assertTrue($both->names('https://issuer.example.com'));
        self::assertFalse($both->names('https://entity.example.com'));
        self::assertTrue($saml->names('https://entity.example.com'));
    }

    /**
     * A preset with an organisation claim is for a shared issuer; one without
     * is not.
     *
     * @return void
     */
    public function testAnOrganizationClaimMarksASharedIssuer(): void
    {
        self::assertTrue((new Preset('acme', 'oidc', organizationClaim: 'hd'))->isSharedIssuer());
        self::assertFalse((new Preset('acme', 'oidc'))->isSharedIssuer());
    }

    /**
     * Rows of `[name, protocol, claim]`: presets refused.
     *
     * @return iterable<string, array{0: string, 1: string, 2: ?string}>
     */
    public static function provideRefusedPresets(): iterable
    {
        yield from [
            'an empty name'      => ['', 'oidc', null],
            'an upper-case name' => ['Acme', 'oidc', null],
            'a dashed name'      => ['acme-sso', 'oidc', null],
            'a long name'        => [str_repeat('a', 65), 'oidc', null],
            'an empty protocol'  => ['acme', '', null],
            'a dotted protocol'  => ['acme', 'saml.2', null],
            'an empty claim'     => ['acme', 'oidc', ''],
        ];
    }

    /**
     * A preset needs a lower-case name and protocol, and a claim that is a name
     * or none.
     *
     * @param  string  $name
     * @param  string  $protocol
     * @param  ?string  $claim
     * @return void
     */
    #[DataProvider('provideRefusedPresets')]
    public function testRefusesAMalformedPreset(string $name, string $protocol, ?string $claim): void
    {
        $this->expectException(\InvalidArgumentException::class);

        new Preset($name, $protocol, organizationClaim: $claim);
    }
}
