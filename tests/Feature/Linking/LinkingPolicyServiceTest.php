<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Administration\ActingIdentity;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\Enums\ConnectionStatus;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Contracts\Freshness;
use SineMacula\Laravel\Sso\Events\ConnectionDisabled;
use SineMacula\Laravel\Sso\Events\ConnectionUpdated;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;
use SineMacula\Laravel\Sso\Linking\DomainLinkEligibility;
use SineMacula\Laravel\Sso\Models\AuthorizationRequest;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Models\HandoffCode;
use SineMacula\Laravel\Sso\Models\Link;
use SineMacula\Laravel\Sso\Protocols\Preset;
use SineMacula\Laravel\Sso\Protocols\ProtocolManager;
use SineMacula\Laravel\Sso\Testing\FakeFreshness;
use Tests\Concerns\CapturesLogs;
use Tests\Fixtures\Protocols\VerifyingDriver;

/**
 * Feature tests for the helper that turns a connection's linking by a verified
 * domain on and off and changes its settings (SSO-8.8, SSO-2.12, SSO-2.13,
 * SSO-2.2): off by default; on only with an explicit classification; a known
 * shared issuer enforcing `shared` under its claim, which configuration may add
 * to and never downgrade; SAML's attribute and acknowledgement; every bound of
 * what is given; freshness first; and, in one transaction, the linking version
 * raised and reservations deleted, with no trust change and no flow voided.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LinkingPolicyService::class)]
#[CoversClass(DomainLinkEligibility::class)]
#[CoversClass(Preset::class)]
final class LinkingPolicyServiceTest extends LinkingTestCase
{
    use CapturesLogs;

    /** @var string A protocol-neutral issuer no list knows. */
    private const string PLAIN_ISSUER = 'https://plain.example.com';

    /** @var string Google's issuer. */
    private const string GOOGLE = 'https://accounts.google.com';

    /** @var string A SAML entity id no list knows. */
    private const string ENTITY_ID = 'https://idp.example.com/saml';

    /** @var string A SAML attribute format. */
    private const string URI_FORMAT = 'urn:oasis:names:tc:SAML:2.0:attrname-format:uri';

    /** @var string The organisation's expected value, which nothing may show. */
    private const string ORGANIZATION = 'the-organisation-value';

    /** @var \SineMacula\Laravel\Sso\Testing\FakeFreshness The freshness contract. */
    private FakeFreshness $freshness;

    /**
     * Bind a freshness contract that answers `fresh`, and turn SAML on.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->freshness = FakeFreshness::fresh();

        $this->app?->instance(Freshness::class, $this->freshness);

        config()->set('sso.features.saml2', true);
    }

    /**
     * A connection's settings are off and unset by default, read in whole; an
     * unknown connection and another tenant's are `null`.
     *
     * @return void
     */
    public function testLinkingIsOffByDefault(): void
    {
        $connection = $this->plain();

        self::assertSame([
            'enabled'               => false,
            'issuer_class'          => null,
            'organization_claim'    => null,
            'organization_value'    => null,
            'saml_attribute'        => null,
            'saml_attribute_format' => null,
            'acknowledged'          => false,
            'version'               => 0,
        ], self::service()->get('tenant-1', $connection->id));

        self::assertNull(self::service()->get('tenant-2', $connection->id));
        self::assertNull(self::service()->get('tenant-1', '01jbexampleconnection00000'));
    }

    /**
     * Rows of `[protocol, issuer, what is given besides enabled, the
     * violations]`.
     *
     * @return iterable<string, array{0: string, 1: string, 2: array<string, mixed>, 3: list<array{0: string, 1: string}>}>
     */
    public static function provideEnablings(): iterable
    {
        $shared = ['issuer_class' => 'shared', 'organization_claim' => 'org', 'organization_value' => self::ORGANIZATION];
        $single = ['issuer_class' => 'single_organization', 'acknowledged' => true];
        $google = ['issuer_class' => 'shared', 'organization_claim' => 'hd', 'organization_value' => self::ORGANIZATION];
        $slack  = ['issuer_class' => 'shared', 'organization_claim' => 'https://slack.com/team_id', 'organization_value' => self::ORGANIZATION];
        $saml   = ['saml_attribute' => 'mail', 'saml_attribute_format' => self::URI_FORMAT, 'acknowledged' => true];

        $noOrganization = [['organization_claim', 'required'], ['organization_value', 'required']];

        yield 'unclassified' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, [], [['issuer_class', 'required']]];
        yield 'classified as nothing' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['issuer_class' => null], [['issuer_class', 'required']]];
        yield 'shared' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, $shared, []];
        yield 'shared with no claim or value' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['issuer_class' => 'shared'], $noOrganization];
        yield 'shared with no value' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['organization_value' => null] + $shared, [['organization_value', 'required']]];
        yield 'shared with no claim' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['organization_claim' => null] + $shared, [['organization_claim', 'required']]];
        yield 'one organisation' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, $single, []];
        yield 'one organisation with no acknowledgement' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['issuer_class' => 'single_organization'], [['acknowledged', 'required']]];
        yield 'one organisation with it refused' => [VerifyingDriver::NAME, self::PLAIN_ISSUER, ['acknowledged' => false] + $single, [['acknowledged', 'required']]];
        yield 'Google' => ['oidc', self::GOOGLE, $google, []];
        yield 'Slack' => ['oidc', 'https://slack.com', $slack, []];
        yield 'Slack as one organisation' => ['oidc', 'https://slack.com', $single + $slack, [['issuer_class', 'not_allowed']]];
        yield 'Slack under another claim' => ['oidc', 'https://slack.com', ['organization_claim' => 'team'] + $slack, [['organization_claim', 'not_allowed']]];
        yield 'Slack with no value' => ['oidc', 'https://slack.com', ['organization_value' => null] + $slack, [['organization_value', 'required']]];
        yield 'Google without the https' => ['oidc', 'accounts.google.com', $google, []];
        yield 'Google as one organisation' => ['oidc', self::GOOGLE, $single, [['issuer_class', 'not_allowed'], ...$noOrganization]];
        yield 'Google as one organisation, claim given' => ['oidc', self::GOOGLE, $single + $google, [['issuer_class', 'not_allowed']]];
        yield 'Google unclassified' => ['oidc', self::GOOGLE, [], [['issuer_class', 'required'], ...$noOrganization]];
        yield 'Google under another claim' => ['oidc', self::GOOGLE, ['organization_claim' => 'org'] + $google, [['organization_claim', 'not_allowed']]];
        yield 'Google with no value' => ['oidc', self::GOOGLE, ['organization_value' => null] + $google, [['organization_value', 'required']]];
        yield 'Microsoft Entra' => ['oidc', 'https://login.microsoftonline.com/the-directory/v2.0', ['organization_claim' => 'tid'] + $google, []];
        yield 'Microsoft Entra as one organisation' => [
            'oidc',
            'https://login.microsoftonline.com/the-directory/v2.0',
            $single,
            [['issuer_class', 'not_allowed'], ...$noOrganization],
        ];
        yield 'SAML' => ['saml2', self::ENTITY_ID, $saml + $shared, []];
        yield 'SAML of one organisation' => ['saml2', self::ENTITY_ID, $saml + $single, []];
        yield 'SAML with no attribute' => ['saml2', self::ENTITY_ID, ['saml_attribute' => null] + $saml + $shared, [['saml_attribute', 'required']]];
        yield 'SAML with no format' => ['saml2', self::ENTITY_ID, ['saml_attribute_format' => null] + $saml + $shared, [['saml_attribute_format', 'required']]];
        yield 'SAML with no acknowledgement' => ['saml2', self::ENTITY_ID, ['acknowledged' => false] + $saml + $shared, [['acknowledged', 'required']]];
        yield 'SAML with nothing' => [
            'saml2',
            self::ENTITY_ID,
            [],
            [['issuer_class', 'required'], ['saml_attribute', 'required'], ['saml_attribute_format', 'required'], ['acknowledged', 'required']],
        ];
        yield 'Entra over SAML under another attribute' => [
            'saml2',
            'https://sts.windows.net/the-directory/',
            $saml + $shared,
            [['organization_claim', 'not_allowed']],
        ];
        yield 'Entra over SAML' => [
            'saml2',
            'https://sts.windows.net/the-directory/',
            ['organization_claim' => 'http://schemas.microsoft.com/identity/claims/tenantid'] + $saml + $shared,
            [],
        ];
    }

    /**
     * Turning linking on is judged on the settings as a whole, and answers
     * every violation, each naming its setting and code, in order.
     *
     * @param  string  $protocol
     * @param  string  $issuer
     * @param  array<string, mixed>  $given
     * @param  list<array{0: string, 1: string}>  $violations
     * @return void
     */
    #[DataProvider('provideEnablings')]
    public function testTurningLinkingOn(string $protocol, string $issuer, array $given, array $violations): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol, 'settings' => [$protocol === 'saml2' ? 'idp_entity_id' : 'issuer' => $issuer]]);
        $result     = self::service()->change('tenant-1', $connection->id, ['enabled' => true, ...$given]);

        self::assertSame($violations, self::violations($result));
        self::assertSame($violations === [], $result->isChanged());
        self::assertSame($violations !== [], $result->isInvalid());
        self::assertSame($violations === [], Connection::query()->whereKey($connection->id)->sole()->linking_enabled);
    }

    /**
     * Turning it on writes every setting, raises the linking version by one,
     * leaves the trust version alone, names what changed, and reports it naming
     * the actor and no value.
     *
     * @return void
     */
    public function testAChangeWritesAndReportsNamesAlone(): void
    {
        $connection = $this->plain();
        $actor      = new ActingIdentity('App\Models\User', '42');

        $result = self::service()->change('tenant-1', $connection->id, [
            'enabled'            => true,
            'issuer_class'       => 'shared',
            'organization_claim' => 'org',
            'organization_value' => self::ORGANIZATION,
        ], $actor);

        $names = ['linking.enabled', 'linking.issuer_class', 'linking.organization_claim', 'linking.organization_value'];
        $row   = Connection::query()->whereKey($connection->id)->sole();

        self::assertSame(ConnectionStatus::UPDATED, $result->status);
        self::assertSame($names, $result->changedSettings);
        self::assertSame($connection->id, $result->connection?->id);
        self::assertSame([
            'enabled'               => true,
            'issuer_class'          => 'shared',
            'organization_claim'    => 'org',
            'organization_value'    => self::ORGANIZATION,
            'saml_attribute'        => null,
            'saml_attribute_format' => null,
            'acknowledged'          => false,
            'version'               => 1,
        ], $row->getLinkingSettings());
        self::assertSame(0, $row->trust_version);
        self::assertSame(0, $row->links_version);

        $this->freshness->assertAsked(FreshnessOperation::CONNECTION_TRUST);

        $event = $this->recordedEvents()[0] ?? null;

        self::assertInstanceOf(ConnectionUpdated::class, $event);
        self::assertSame($names, $event->changedSettings);
        self::assertSame($connection->id, $event->context->connectionId);
        self::assertSame('42', $event->context->actingIdentityId);
        self::assertCount(1, $this->recordedEvents());
        self::assertStringNotContainsString(self::ORGANIZATION, (string) json_encode($result));
        self::assertStringNotContainsString(self::ORGANIZATION, print_r($event, true));
    }

    /**
     * A change deletes the open reservations and raises both counters, with no
     * trust change and nothing voided, so the code goes on to meet
     * `reservation_invalid`, and no `ConnectionDisabled` is reported.
     *
     * @return void
     */
    public function testAChangeVoidsReservationsAndNoFlow(): void
    {
        $start      = $this->start();
        $completion = $this->complete();

        $this->start();

        $before = Connection::query()->whereKey($this->connection->id)->sole();

        self::assertSame(1, Link::query()->count());
        self::assertSame(1, $before->links_version);

        $this->connection->forceFill(['linking_acknowledged_at' => null])->save();

        $result = self::service()->change('tenant-1', $this->connection->id, ['acknowledged' => true]);
        $after  = Connection::query()->whereKey($this->connection->id)->sole();

        self::assertSame(['linking.acknowledged'], $result->changedSettings);
        self::assertSame(0, Link::query()->count());
        self::assertSame(1, $after->linking_version);
        self::assertSame(2, $after->links_version);
        self::assertSame($before->trust_version, $after->trust_version);
        self::assertSame(0, HandoffCode::query()->whereNotNull('voided_at')->count());
        self::assertSame(0, AuthorizationRequest::query()->whereNotNull('voided_at')->count());
        self::assertSame([], array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof ConnectionDisabled));
        self::assertSame(FailureReason::RESERVATION_INVALID, $this->admit($completion, $start)->reason);
    }

    /**
     * Turning linking off asks nothing else of the settings, whatever the
     * feature says, and keeps what it holds; a reservation goes with it.
     *
     * @return void
     */
    public function testTurningLinkingOffIsAlwaysAllowed(): void
    {
        $this->start();
        $this->complete();

        config()->set('sso.features.domain_linking', false);

        $result = self::service()->change('tenant-1', $this->connection->id, ['enabled' => false]);
        $row    = Connection::query()->whereKey($this->connection->id)->sole();

        self::assertSame(['linking.enabled'], $result->changedSettings);
        self::assertFalse($row->linking_enabled);
        self::assertSame('single_organization', $row->linking_issuer_class);
        self::assertSame(0, Link::query()->count());
    }

    /**
     * Turned off, the settings may stand incomplete, and each is still judged.
     *
     * @return void
     */
    public function testIncompleteSettingsMayStandWhileItIsOff(): void
    {
        $connection = $this->plain();

        $result = self::service()->change('tenant-1', $connection->id, ['issuer_class' => 'shared']);

        self::assertSame(['linking.issuer_class'], $result->changedSettings);
        self::assertFalse(Connection::query()->whereKey($connection->id)->sole()->linking_enabled);
    }

    /**
     * Linking cannot be turned on while the feature is off, however complete
     * the settings.
     *
     * @return void
     */
    public function testTheFeatureMustBeOn(): void
    {
        config()->set('sso.features.domain_linking', false);

        $connection = $this->plain();
        $result     = self::service()->change('tenant-1', $connection->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true]);

        self::assertSame([['enabled', 'unsupported']], self::violations($result));
        self::assertSame(FailureReason::SETTINGS_INVALID, $result->reason);
        self::assertFalse(Connection::query()->whereKey($connection->id)->sole()->linking_enabled);
    }

    /**
     * Giving what the connection holds is `unchanged`: nothing is written or
     * raised and nothing reported; neither is an empty change.
     *
     * @return void
     */
    public function testAChangeOfNothingIsUnchanged(): void
    {
        $connection = $this->plain();
        $given      = ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true];

        self::service()->change('tenant-1', $connection->id, $given);

        $count = count($this->recordedEvents());

        foreach ([$given, []] as $again) {

            $result = self::service()->change('tenant-1', $connection->id, $again);

            self::assertSame(ConnectionStatus::UNCHANGED, $result->status);
            self::assertSame([], $result->changedSettings);
            self::assertSame($connection->id, $result->connection?->id);
        }

        self::assertSame(1, Connection::query()->whereKey($connection->id)->sole()->linking_version);
        self::assertCount($count, $this->recordedEvents());
    }

    /**
     * The acknowledgement is recorded with its time, and given again changes
     * nothing, so its first time stands.
     *
     * @return void
     */
    public function testTheAcknowledgementIsRecordedOnce(): void
    {
        $connection = $this->plain();
        $given      = ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true];
        $first      = $this->clock->now();

        self::service()->change('tenant-1', $connection->id, $given);
        $this->clock->advance(30);
        self::service()->change('tenant-1', $connection->id, $given);

        self::assertSame($first->toIso8601String(), self::acknowledgedAt($connection));
    }

    /**
     * A change that touches nothing the acknowledgement stands for keeps the
     * moment it was given.
     *
     * @return void
     */
    public function testAnAcknowledgementThatStillStandsKeepsItsMoment(): void
    {
        $connection = $this->plain();
        $first      = $this->clock->now();

        self::service()->change('tenant-1', $connection->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true]);

        $this->clock->advance(30);

        self::assertSame(['linking.enabled'], self::service()->change('tenant-1', $connection->id, ['enabled' => false])->changedSettings);
        self::assertSame($first->toIso8601String(), self::acknowledgedAt($connection));
    }

    /**
     * An OIDC connection's issuer is what decides, whatever else its settings
     * hold.
     *
     * @return void
     */
    public function testTheIssuerDecidesOverAnEntityIdAlsoHeld(): void
    {
        $connection = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['issuer' => self::GOOGLE, 'idp_entity_id' => self::PLAIN_ISSUER]]);
        $result     = self::service()->change('tenant-1', $connection->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true]);

        self::assertSame([['issuer_class', 'not_allowed'], ['organization_claim', 'required'], ['organization_value', 'required']], self::violations($result));
    }

    /**
     * An acknowledgement stands for what it was given about: a classification
     * changed without it clears it, and given with the change it is recorded
     * anew; taking it away clears it.
     *
     * @return void
     */
    public function testAnAcknowledgementStandsForWhatItWasGivenAbout(): void
    {
        $connection = $this->plain();
        $shared     = ['issuer_class' => 'shared', 'organization_claim' => 'org', 'organization_value' => self::ORGANIZATION];

        self::service()->change('tenant-1', $connection->id, ['issuer_class' => 'single_organization', 'acknowledged' => true]);

        $cleared = self::service()->change('tenant-1', $connection->id, $shared);

        self::assertSame(['linking.issuer_class', 'linking.organization_claim', 'linking.organization_value', 'linking.acknowledged'], $cleared->changedSettings);
        self::assertNull(self::acknowledgedAt($connection));

        self::service()->change('tenant-1', $connection->id, ['acknowledged' => true]);

        $this->clock->advance(30);

        $again = self::service()->change('tenant-1', $connection->id, ['issuer_class' => 'single_organization', 'acknowledged' => true]);

        self::assertSame(['linking.issuer_class'], $again->changedSettings);
        self::assertSame($this->clock->now()->toIso8601String(), self::acknowledgedAt($connection));

        $taken = self::service()->change('tenant-1', $connection->id, ['acknowledged' => false]);

        self::assertSame(['linking.acknowledged'], $taken->changedSettings);
        self::assertNull(self::acknowledgedAt($connection));
    }

    /**
     * Rows of `[a change to what an acknowledgement stands for]`.
     *
     * @return iterable<string, array{0: array<string, string>}>
     */
    public static function provideAttributeChanges(): iterable
    {
        yield 'the name' => [['saml_attribute' => 'email']];
        yield 'the format' => [['saml_attribute_format' => 'urn:oasis:names:tc:SAML:2.0:attrname-format:basic']];
    }

    /**
     * On SAML, changing the attribute's `Name` or `NameFormat` clears the
     * acknowledgement, and so cannot stand while linking is on.
     *
     * @param  array<string, string>  $change
     * @return void
     */
    #[DataProvider('provideAttributeChanges')]
    public function testChangingTheSamlAttributeNeedsTheAcknowledgementAgain(array $change): void
    {
        $connection = $this->makeConnection(['protocol' => 'saml2', 'settings' => ['idp_entity_id' => self::ENTITY_ID]]);

        self::service()->change('tenant-1', $connection->id, [
            'enabled'               => true,
            'issuer_class'          => 'single_organization',
            'saml_attribute'        => 'mail',
            'saml_attribute_format' => self::URI_FORMAT,
            'acknowledged'          => true,
        ]);

        self::assertSame([['acknowledged', 'required']], self::violations(self::service()->change('tenant-1', $connection->id, $change)));
        self::assertTrue(self::service()->change('tenant-1', $connection->id, [...$change, 'acknowledged' => true])->isChanged());
    }

    /**
     * Rows of `[protocol, what is given, the violations]`: each setting judged
     * alone, whatever else is on, at every bound.
     *
     * @return iterable<string, array{0: string, 1: array<int|string, mixed>, 2: list<array{0: string, 1: string}>}>
     */
    public static function provideGiven(): iterable
    {
        $oidc = 'oidc';
        $saml = 'saml2';

        yield 'an unknown setting' => [$oidc, ['issuer' => 'x'], [['issuer', 'unknown']]];
        yield 'a key that is a number' => [$oidc, [3 => 'x'], [['3', 'unknown']]];
        yield 'a key that cannot be named' => [$oidc, ["bad\x01key" => 'x'], [['settings', 'unknown']]];
        yield 'enabled as a string' => [$oidc, ['enabled' => 'true'], [['enabled', 'invalid_type']]];
        yield 'enabled as a number' => [$oidc, ['enabled' => 1], [['enabled', 'invalid_type']]];
        yield 'enabled as nothing' => [$oidc, ['enabled' => null], [['enabled', 'invalid_type']]];
        yield 'acknowledged as a string' => [$oidc, ['acknowledged' => 'yes'], [['acknowledged', 'invalid_type']]];
        yield 'acknowledged as nothing' => [$oidc, ['acknowledged' => null], [['acknowledged', 'invalid_type']]];
        yield 'a class that is no string' => [$oidc, ['issuer_class' => 1], [['issuer_class', 'invalid_type']]];
        yield 'a class no one knows' => [$oidc, ['issuer_class' => 'Shared'], [['issuer_class', 'not_allowed']]];
        yield 'the longest claim' => [$oidc, ['organization_claim' => str_repeat('c', 255)], []];
        yield 'one byte over the longest claim' => [$oidc, ['organization_claim' => str_repeat('c', 256)], [['organization_claim', 'too_long']]];
        yield 'an empty claim' => [$oidc, ['organization_claim' => ''], [['organization_claim', 'required']]];
        yield 'a claim that is no string' => [$oidc, ['organization_claim' => ['hd']], [['organization_claim', 'invalid_type']]];
        yield 'a claim with a space over OIDC' => [$oidc, ['organization_claim' => 'h d'], [['organization_claim', 'invalid_format']]];
        yield 'a claim with a space over SAML' => [$saml, ['organization_claim' => 'Tenant Id'], []];
        yield 'a claim with a control character' => [$saml, ['organization_claim' => "h\x01d"], [['organization_claim', 'invalid_format']]];
        yield 'the subject as the claim' => [$oidc, ['organization_claim' => 'sub'], [['organization_claim', 'reserved']]];
        yield 'the issuer as the claim' => [$oidc, ['organization_claim' => 'iss'], [['organization_claim', 'reserved']]];
        yield 'the audience as the claim' => [$oidc, ['organization_claim' => 'aud'], [['organization_claim', 'reserved']]];
        yield 'the email as the claim' => [$oidc, ['organization_claim' => 'email'], [['organization_claim', 'reserved']]];
        yield 'a protocol value over SAML is just a name' => [$saml, ['organization_claim' => 'sub'], []];
        yield 'a protocol value on another protocol is just a name' => [VerifyingDriver::NAME, ['organization_claim' => 'sub'], []];
        yield 'the longest value' => [$oidc, ['organization_value' => str_repeat('v', 255)], []];
        yield 'one byte over the longest value' => [$oidc, ['organization_value' => str_repeat('v', 256)], [['organization_value', 'too_long']]];
        yield 'an empty value' => [$oidc, ['organization_value' => ''], [['organization_value', 'required']]];
        yield 'a value that is no string' => [$oidc, ['organization_value' => 7], [['organization_value', 'invalid_type']]];
        yield 'a value with a space' => [$oidc, ['organization_value' => 'an organisation'], []];
        yield 'a value with a control character' => [$oidc, ['organization_value' => "an\x01organisation"], [['organization_value', 'invalid_format']]];
        yield 'the longest attribute' => [$saml, ['saml_attribute' => str_repeat('a', 1024)], []];
        yield 'one byte over the longest attribute' => [$saml, ['saml_attribute' => str_repeat('a', 1025)], [['saml_attribute', 'too_long']]];
        yield 'an attribute with a space' => [$saml, ['saml_attribute' => 'E Mail'], []];
        yield 'an attribute over OIDC' => [$oidc, ['saml_attribute' => 'mail'], [['saml_attribute', 'unsupported']]];
        yield 'an attribute cleared over OIDC' => [$oidc, ['saml_attribute' => null], []];
        yield 'the longest format' => [$saml, ['saml_attribute_format' => str_repeat('f', 255)], []];
        yield 'one byte over the longest format' => [$saml, ['saml_attribute_format' => str_repeat('f', 256)], [['saml_attribute_format', 'too_long']]];
        yield 'a format with a space' => [$saml, ['saml_attribute_format' => 'a format'], [['saml_attribute_format', 'invalid_format']]];
        yield 'a format over OIDC' => [$oidc, ['saml_attribute_format' => self::URI_FORMAT], [['saml_attribute_format', 'unsupported']]];
        yield 'two at once' => [$oidc, ['enabled' => 'x', 'organization_claim' => ''], [['enabled', 'invalid_type'], ['organization_claim', 'required']]];
    }

    /**
     * Each setting is judged by its type and bounds, naming it and a code.
     *
     * @param  string  $protocol
     * @param  array<int|string, mixed>  $given
     * @param  list<array{0: string, 1: string}>  $violations
     * @return void
     */
    #[DataProvider('provideGiven')]
    public function testWhatIsGivenIsJudged(string $protocol, array $given, array $violations): void
    {
        $connection = $this->makeConnection(['protocol' => $protocol, 'settings' => [$protocol === 'saml2' ? 'idp_entity_id' : 'issuer' => self::PLAIN_ISSUER]]);
        $result     = self::service()->change('tenant-1', $connection->id, $given);

        self::assertSame($violations, self::violations($result));
        self::assertSame($violations !== [], $result->isInvalid());

        if ($violations === []) {
            return;
        }

        self::assertSame(0, Connection::query()->whereKey($connection->id)->sole()->linking_version);
    }

    /**
     * A refusal names the setting and never echoes what was given.
     *
     * @return void
     */
    public function testAViolationNeverEchoesTheValue(): void
    {
        $result = self::service()->change('tenant-1', $this->plain()->id, ['organization_value' => self::ORGANIZATION . "\x01"]);

        self::assertSame([['organization_value', 'invalid_format']], self::violations($result));
        self::assertStringNotContainsString(self::ORGANIZATION, (string) json_encode($result));
    }

    /**
     * What is given can be cleared with `null`.
     *
     * @return void
     */
    public function testASettingIsClearedWithNull(): void
    {
        $connection = $this->plain();

        self::service()->change('tenant-1', $connection->id, ['organization_claim' => 'org', 'organization_value' => self::ORGANIZATION]);

        $result = self::service()->change('tenant-1', $connection->id, ['organization_claim' => null, 'organization_value' => null]);

        self::assertSame(['linking.organization_claim', 'linking.organization_value'], $result->changedSettings);
        self::assertNull(Connection::query()->whereKey($connection->id)->sole()->linking_organization_value);
    }

    /**
     * Stale authentication is refused before anything else is read or written,
     * and reports nothing.
     *
     * @return void
     */
    public function testStaleAuthenticationIsRefused(): void
    {
        $this->app?->instance(Freshness::class, FakeFreshness::stale());

        $connection = $this->plain();
        $result     = self::service()->change('tenant-1', $connection->id, ['enabled' => true, 'issuer_class' => 'not-a-class']);

        self::assertSame(ConnectionStatus::REFUSED, $result->status);
        self::assertSame(FailureReason::FRESHNESS_REQUIRED, $result->reason);
        self::assertSame(0, Connection::query()->whereKey($connection->id)->sole()->linking_version);
        self::assertSame([], array_filter($this->recordedEvents(), static fn ($event): bool => $event instanceof ConnectionUpdated));
    }

    /**
     * An unknown connection and another tenant's are the same refusal, before
     * freshness is asked.
     *
     * @return void
     */
    public function testAnotherTenantsConnectionIsNotFound(): void
    {
        $connection = $this->plain();

        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, self::service()->change('tenant-2', $connection->id, ['enabled' => false])->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, self::service()->change('TENANT-1', $connection->id, ['enabled' => false])->reason);
        self::assertSame(FailureReason::CONNECTION_NOT_FOUND, self::service()->change('tenant-1', '01jbexampleconnection00000', ['enabled' => false])->reason);

        $this->freshness->assertNotAsked();
    }

    /**
     * A protocol no longer available refuses the change.
     *
     * @return void
     */
    public function testAnUnavailableProtocolIsRefused(): void
    {
        $connection = $this->makeConnection(['protocol' => 'nonesuch']);
        $result     = self::service()->change('tenant-1', $connection->id, ['enabled' => false]);

        self::assertSame(FailureReason::PROTOCOL_UNAVAILABLE, $result->reason);
    }

    /**
     * An empty tenant id is the caller's mistake.
     *
     * @return void
     */
    public function testAnEmptyTenantIdThrows(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A tenant id is 1 to 255 bytes.');

        self::service()->change('', $this->plain()->id, []);
    }

    /**
     * Configuration may add a shared issuer, which then refuses anything else;
     * an entry for a built-in one downgrades nothing.
     *
     * @return void
     */
    public function testConfigurationAddsAndNeverDowngrades(): void
    {
        config()->set('sso.linking.shared_issuers', [self::PLAIN_ISSUER => 'org', self::GOOGLE => 'not-hd']);

        $sharing = ['enabled' => true, 'issuer_class' => 'shared', 'organization_value' => 'x'];
        $added   = $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'settings' => ['issuer' => self::PLAIN_ISSUER]]);
        $built   = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['issuer' => self::GOOGLE]]);

        self::assertSame(
            [['issuer_class', 'not_allowed'], ['organization_claim', 'required'], ['organization_value', 'required']],
            self::violations(self::service()->change('tenant-1', $added->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true])),
        );

        self::assertSame(
            [['organization_claim', 'not_allowed']],
            self::violations(self::service()->change('tenant-1', $built->id, ['organization_claim' => 'not-hd', ...$sharing])),
        );

        self::assertTrue(self::service()->change('tenant-1', $built->id, ['organization_claim' => 'hd', ...$sharing])->isChanged());
    }

    /**
     * Configuration cannot change the claim of an issuer a preset names, in
     * either protocol: the preset's claim still stands, and the claim the
     * configuration named is refused. An issuer no preset of the protocol
     * names, even one shaped like another protocol's, is the configuration's.
     *
     * @return void
     */
    public function testConfigurationCannotChangeAPresetsClaim(): void
    {
        $eligibility = app(DomainLinkEligibility::class);
        $oidc        = 'https://login.microsoftonline.com/the-directory/v2.0';
        $saml        = 'https://sts.windows.net/the-directory/';

        self::assertSame('https://slack.com/team_id', $eligibility->requiredClaim('oidc', 'https://slack.com'));
        self::assertSame('tid', $eligibility->requiredClaim('oidc', $oidc));

        config()->set('sso.linking.shared_issuers', [$oidc => 'preferred_username', $saml => 'preferred_username', self::PLAIN_ISSUER => 'org']);

        $eligibility = app(DomainLinkEligibility::class);

        self::assertSame('tid', $eligibility->requiredClaim('oidc', $oidc));
        self::assertSame('http://schemas.microsoft.com/identity/claims/tenantid', $eligibility->requiredClaim('saml2', $saml));
        self::assertSame('preferred_username', $eligibility->requiredClaim('saml2', $oidc));
        self::assertSame('org', $eligibility->requiredClaim('oidc', self::PLAIN_ISSUER));
        self::assertNull($eligibility->requiredClaim('oidc', 'https://unknown.example.com'));

        $entra   = $this->makeConnection(['protocol' => 'oidc', 'settings' => ['issuer' => $oidc]]);
        $sharing = ['enabled' => true, 'issuer_class' => 'shared', 'organization_value' => 'x'];

        self::assertSame(
            [['organization_claim', 'not_allowed']],
            self::violations(self::service()->change('tenant-1', $entra->id, ['organization_claim' => 'preferred_username', ...$sharing])),
        );
        self::assertTrue(self::service()->change('tenant-1', $entra->id, ['organization_claim' => 'tid', ...$sharing])->isChanged());
    }

    /**
     * A registered preset with an organisation claim cannot enable linking
     * without it; one with no claim, or of another protocol, says nothing.
     *
     * @return void
     */
    public function testAPresetWithAnOrganizationClaimEnforcesIt(): void
    {
        $manager = app(ProtocolManager::class);

        $manager->registerPreset(new Preset('plain_no_claim', VerifyingDriver::NAME, ['issuer' => self::PLAIN_ISSUER]));
        $manager->registerPreset(new Preset('plain_other_protocol', 'oidc', ['issuer' => self::PLAIN_ISSUER], [], 'not-this-one'));
        $manager->registerPreset(new Preset('plain_shared', VerifyingDriver::NAME, ['issuer' => self::PLAIN_ISSUER], [], 'org'));

        $connection = $this->plain();

        self::assertSame(
            [['issuer_class', 'not_allowed'], ['organization_claim', 'required'], ['organization_value', 'required']],
            self::violations(self::service()->change('tenant-1', $connection->id, ['enabled' => true, 'issuer_class' => 'single_organization', 'acknowledged' => true])),
        );

        $shared = ['enabled' => true, 'issuer_class' => 'shared', 'organization_claim' => 'org', 'organization_value' => 'x'];

        self::assertTrue(self::service()->change('tenant-1', $connection->id, $shared)->isChanged());
    }

    /**
     * The organisation's value is never logged.
     *
     * @return void
     */
    public function testNothingIsLogged(): void
    {
        $this->captureLogs();

        self::service()->change('tenant-1', $this->plain()->id, ['organization_value' => self::ORGANIZATION]);

        self::assertSame([], $this->capturedLogRecords());
    }

    /**
     * A connection of the driver's protocol with an issuer no list knows.
     *
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private function plain(): Connection
    {
        return $this->makeConnection(['protocol' => VerifyingDriver::NAME, 'settings' => ['issuer' => self::PLAIN_ISSUER]]);
    }

    /**
     * When the connection's acknowledgement was recorded, as it is stored now.
     *
     * @param  \SineMacula\Laravel\Sso\Models\Connection  $connection
     * @return ?string
     */
    private static function acknowledgedAt(Connection $connection): ?string
    {
        return Connection::query()->whereKey($connection->id)->sole()->linking_acknowledged_at?->toIso8601String();
    }

    /**
     * The helper, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Connections\LinkingPolicyService
     */
    private static function service(): LinkingPolicyService
    {
        return app(LinkingPolicyService::class);
    }

    /**
     * Each violation of the result, as its setting and code.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionResult  $result
     * @return list<array{0: string, 1: string}>
     */
    private static function violations(ConnectionResult $result): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $result->violations);
    }
}
