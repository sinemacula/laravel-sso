<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Options;
use SineMacula\Laravel\Sso\Protocols\Saml2\Saml2Settings;
use Tests\Fixtures\Protocols\ExampleConnection;
use Tests\TestCase;

/**
 * Feature tests for a SAML connection's typed options.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Options::class)]
final class Saml2OptionsTest extends TestCase
{
    /**
     * A connection with no settings has every default, and nothing it was not
     * given.
     *
     * @return void
     */
    public function testAppliesTheDefaults(): void
    {
        $options = Saml2Options::of(new ExampleConnection('saml2'));

        self::assertSame([null, null, 'http_redirect', 'name_id', null, 'persistent', null, null, null], [
            $options->idpEntityId, $options->ssoUrl, $options->ssoBinding, $options->subjectSource, $options->subjectAttribute,
            $options->nameIdFormat, $options->maxAuthenticationAgeSeconds, $options->idpInitiatedStartUrl, $options->metadataUrl,
        ]);
        self::assertSame([false, true, false, false, false, false], array_map($options->isOn(...), self::switches()));
        self::assertSame(Saml2Settings::SIGNATURE_ALGORITHMS, $options->listOf(Saml2Setting::SIGNATURE_ALGORITHMS));
        self::assertSame([], $options->listOf(Saml2Setting::REQUESTED_AUTHN_CONTEXT));
        self::assertSame([], $options->listOf(Saml2Setting::IDP_ENTITY_ID));
        self::assertFalse($options->isOn(Saml2Setting::IDP_ENTITY_ID));
        self::assertSame('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent', $options->nameIdFormatUri());
        self::assertSame('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect', $options->ssoBindingUri());
        self::assertSame(Saml2Settings::KEY_TRANSPORT_ALGORITHMS, $options->keyTransportAlgorithms());
        self::assertSame(Saml2Settings::DATA_ENCRYPTION_ALGORITHMS, $options->dataEncryptionAlgorithms());
    }

    /**
     * Every setting given is read under its property.
     *
     * @return void
     */
    public function testReadsEverySettingGiven(): void
    {
        $cbc     = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';
        $options = Saml2Options::of(new ExampleConnection('saml2', [
            'idp_entity_id'                  => 'urn:example:idp',
            'sso_url'                        => 'https://idp.example.com/sso',
            'sso_binding'                    => 'http_post',
            'subject_source'                 => 'attribute',
            'subject_attribute'              => 'employeeNumber',
            'name_id_format'                 => 'email',
            'sign_authn_requests'            => true,
            'want_assertions_signed'         => false,
            'require_encrypted_assertions'   => true,
            'signature_algorithms'           => ['http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'],
            'encryption_algorithms'          => ['http://www.w3.org/2009/xmlenc11#rsa-oaep', $cbc],
            'force_authn'                    => true,
            'requested_authn_context'        => ['urn:x:a', 'urn:x:b'],
            'max_authentication_age_seconds' => 3600,
            'idp_initiated'                  => true,
            'idp_initiated_start_url'        => 'https://app.example.com/start',
            'metadata_url'                   => 'https://idp.example.com/metadata',
            'metadata_refresh'               => true,
        ]));

        self::assertSame(
            ['urn:example:idp', 'https://idp.example.com/sso', 'http_post', 'attribute', 'employeeNumber', 'email'],
            [$options->idpEntityId, $options->ssoUrl, $options->ssoBinding, $options->subjectSource, $options->subjectAttribute, $options->nameIdFormat],
        );
        self::assertSame(
            [3600, 'https://app.example.com/start', 'https://idp.example.com/metadata'],
            [$options->maxAuthenticationAgeSeconds, $options->idpInitiatedStartUrl, $options->metadataUrl],
        );
        self::assertSame([true, false, true, true, true, true], array_map($options->isOn(...), self::switches()));
        self::assertSame(['urn:x:a', 'urn:x:b'], $options->listOf(Saml2Setting::REQUESTED_AUTHN_CONTEXT));
        self::assertSame('urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', $options->nameIdFormatUri());
        self::assertSame('urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST', $options->ssoBindingUri());
        self::assertSame(['http://www.w3.org/2009/xmlenc11#rsa-oaep'], $options->keyTransportAlgorithms());
        self::assertSame([$cbc], $options->dataEncryptionAlgorithms());
        $unspecified = Saml2Options::of(new ExampleConnection('saml2', ['name_id_format' => 'unspecified']));

        self::assertSame('urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', $unspecified->nameIdFormatUri());
    }

    /**
     * A setting of the wrong type is read as not given: never a value it does
     * not hold.
     *
     * @return void
     */
    public function testReadsAMalformedSettingAsNotGiven(): void
    {
        $options = Saml2Options::of(new ExampleConnection('saml2', [
            'idp_entity_id'                  => 5,
            'sso_binding'                    => 'soap',
            'name_id_format'                 => 'transient',
            'sign_authn_requests'            => 'yes',
            'signature_algorithms'           => 'rsa',
            'requested_authn_context'        => ['urn:x:a', 7],
            'max_authentication_age_seconds' => '3600',
        ]));

        self::assertNull($options->idpEntityId);
        self::assertNull($options->maxAuthenticationAgeSeconds);
        self::assertFalse($options->isOn(Saml2Setting::SIGN_AUTHN_REQUESTS));
        self::assertSame([], $options->listOf(Saml2Setting::SIGNATURE_ALGORITHMS));
        self::assertSame(['urn:x:a'], $options->listOf(Saml2Setting::REQUESTED_AUTHN_CONTEXT));
        self::assertSame(Saml2Options::NAME_ID_FORMATS['persistent'], $options->nameIdFormatUri());
        self::assertSame(Saml2Options::BINDINGS['http_redirect'], $options->ssoBindingUri());
        self::assertSame('urn:oasis:names:tc:SAML:2.0:nameid-format:transient', Saml2Options::TRANSIENT);
    }

    /**
     * The switches, in the order the options keep them.
     *
     * @return list<\SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting>
     */
    private static function switches(): array
    {
        return [
            Saml2Setting::SIGN_AUTHN_REQUESTS, Saml2Setting::WANT_ASSERTIONS_SIGNED, Saml2Setting::REQUIRE_ENCRYPTED_ASSERTIONS,
            Saml2Setting::FORCE_AUTHN, Saml2Setting::IDP_INITIATED, Saml2Setting::METADATA_REFRESH,
        ];
    }
}
