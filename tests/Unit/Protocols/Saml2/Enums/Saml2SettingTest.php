<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Saml2\Enums;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Protocols\Saml2\Enums\Saml2Setting;

/**
 * Unit tests for the names of a SAML connection's settings and how a change to
 * each is classified: the freshness it needs, and whether it may change what
 * existing subjects mean.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Saml2Setting::class)]
final class Saml2SettingTest extends TestCase
{
    /**
     * The names are these, in this order: a name is never renamed or reused.
     *
     * @return void
     */
    public function testTheNamesAreStable(): void
    {
        self::assertSame([
            'idp_entity_id', 'sso_url', 'sso_binding', 'subject_source', 'subject_attribute', 'name_id_format',
            'sign_authn_requests', 'want_assertions_signed', 'require_encrypted_assertions', 'signature_algorithms',
            'encryption_algorithms', 'force_authn', 'requested_authn_context', 'max_authentication_age_seconds', 'idp_initiated',
            'idp_initiated_start_url', 'metadata_url', 'metadata_refresh',
        ], array_column(Saml2Setting::cases(), 'value'));
    }

    /**
     * Trust, endpoints, subject, what a signature or algorithm must be, what
     * the provider's authentication must prove and the metadata refresh need
     * `sso.connection.trust`; IdP-initiated sign-in needs its own; request
     * options need none.
     *
     * @return void
     */
    public function testEachChangeNeedsTheFreshnessOfItsOperation(): void
    {
        $operations = [];

        foreach (Saml2Setting::cases() as $setting) {
            $operations[$setting->value] = $setting->freshness()?->value;
        }

        self::assertSame([
            'idp_entity_id'                  => FreshnessOperation::CONNECTION_TRUST->value,
            'sso_url'                        => FreshnessOperation::CONNECTION_TRUST->value,
            'sso_binding'                    => FreshnessOperation::CONNECTION_TRUST->value,
            'subject_source'                 => FreshnessOperation::CONNECTION_TRUST->value,
            'subject_attribute'              => FreshnessOperation::CONNECTION_TRUST->value,
            'name_id_format'                 => FreshnessOperation::CONNECTION_TRUST->value,
            'sign_authn_requests'            => null,
            'want_assertions_signed'         => FreshnessOperation::CONNECTION_TRUST->value,
            'require_encrypted_assertions'   => FreshnessOperation::CONNECTION_TRUST->value,
            'signature_algorithms'           => FreshnessOperation::CONNECTION_TRUST->value,
            'encryption_algorithms'          => FreshnessOperation::CONNECTION_TRUST->value,
            'force_authn'                    => null,
            'requested_authn_context'        => FreshnessOperation::CONNECTION_TRUST->value,
            'max_authentication_age_seconds' => FreshnessOperation::CONNECTION_TRUST->value,
            'idp_initiated'                  => FreshnessOperation::CONNECTION_IDP_INITIATED->value,
            'idp_initiated_start_url'        => FreshnessOperation::CONNECTION_IDP_INITIATED->value,
            'metadata_url'                   => FreshnessOperation::CONNECTION_TRUST->value,
            'metadata_refresh'               => FreshnessOperation::CONNECTION_TRUST->value,
        ], $operations);
    }

    /**
     * The entity id, the subject source and attribute, and the NameID format
     * may change what existing subjects mean (SSO-2.13).
     *
     * @return void
     */
    public function testTheSubjectSettingsAlterSubjects(): void
    {
        self::assertSame(['idp_entity_id', 'subject_source', 'subject_attribute', 'name_id_format'], Saml2Setting::subjectNames());
        self::assertTrue(Saml2Setting::NAME_ID_FORMAT->altersSubject());
        self::assertFalse(Saml2Setting::SSO_URL->altersSubject());

        foreach (Saml2Setting::subjectNames() as $name) {
            self::assertSame(FreshnessOperation::CONNECTION_TRUST, Saml2Setting::from($name)->freshness());
        }
    }
}
