<?php

declare(strict_types = 1);

namespace Tests\Feature\Domains;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Domains\DomainsCheck;
use SineMacula\Laravel\Sso\Domains\DomainSettings;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[domains]` and the settings it checks (SSO-3.1 to SSO-3.3,
 * SSO-12.2, SSO-12.3): checked only while the package is in use; the shipped
 * defaults passing; each malformed setting reported with the message the domain
 * operations would fail closed with, naming its key and never its value; the
 * refused domains always holding the public mailbox providers; and the linking
 * maximum age never above a day.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DomainsCheck::class)]
#[CoversClass(DomainSettings::class)]
final class DomainsCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use, however malformed; the
     * shipped defaults pass once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        config()->set('sso.domains.record_name', 'NOT VALID');

        self::assertNull($this->problemsOf(DomainsCheck::class));

        $this->useThePackage();
        config()->set('sso.domains.record_name', '_sso-verification');

        self::assertSame([], $this->problemsOf(DomainsCheck::class));
    }

    /**
     * Settings that are not configured take their defaults: a production-safe
     * record name, the mailbox providers refused, a week's pending expiry, a
     * three-day grace period and a day's linking maximum age.
     *
     * @return void
     */
    public function testUnsetSettingsTakeTheirDefaults(): void
    {
        $this->useThePackage();

        config()->set('sso.domains', ['table' => 'sso_domains']);

        $settings = new DomainSettings(config());

        self::assertSame([], $this->problemsOf(DomainsCheck::class));
        self::assertSame('_sso-verification', $settings->recordName());
        self::assertSame(DomainSettings::PUBLIC_MAILBOX_PROVIDERS, $settings->refused());
        self::assertSame(604800, $settings->pendingExpirySeconds());
        self::assertSame(259200, $settings->recheckGraceSeconds());
        self::assertSame(86400, $settings->linkingMaxAgeSeconds());
    }

    /**
     * The shipped configuration gives the same values.
     *
     * @return void
     */
    public function testTheShippedConfigurationIsTheDefault(): void
    {
        $settings = new DomainSettings(config());

        self::assertSame('_sso-verification', $settings->recordName());
        self::assertSame(604800, $settings->pendingExpirySeconds());
        self::assertSame(259200, $settings->recheckGraceSeconds());
        self::assertSame(86400, $settings->linkingMaxAgeSeconds());
        self::assertContains('gmail.com', $settings->refused());
    }

    /**
     * Configured refused domains are normalised and added to the mailbox
     * providers, each once; none is ever removed.
     *
     * @return void
     */
    public function testConfiguredRefusedDomainsAreAdded(): void
    {
        config()->set('sso.domains.refused', ['Shared.Example.org.', 'gmail.com', 'bücher.de']);

        $refused = (new DomainSettings(config()))->refused();

        self::assertSame([...DomainSettings::PUBLIC_MAILBOX_PROVIDERS, 'shared.example.org', 'xn--bcher-kva.de'], $refused);
    }

    /**
     * Rows of `[settings, problems]`: domain settings and what each reports.
     *
     * @return iterable<string, array{0: array<string, mixed>, 1: list<string>}>
     */
    public static function provideSettings(): iterable
    {
        $record  = 'sso.domains.record_name must be one to four labels of lower-case letters, digits, `-` and `_`, at most 63 characters.';
        $list    = 'sso.domains.refused must be a list of domains.';
        $pending = 'sso.domains.pending_expiry_seconds must be an integer from 3600 to 2592000.';
        $grace   = 'sso.domains.recheck_grace_seconds must be an integer from 0 to 2592000.';
        $linking = 'sso.domains.linking_max_age_seconds must be an integer from 60 to 86400.';

        yield from [
            'valid values as strings' => [
                ['record_name' => '_acme.verify', 'pending_expiry_seconds' => '3600', 'recheck_grace_seconds' => '0', 'linking_max_age_seconds' => '60'],
                [],
            ],
            'a record name in capitals'        => [['record_name' => '_SSO'], [$record]],
            'a record name with a space'       => [['record_name' => '_sso verification'], [$record]],
            'a record name of five labels'     => [['record_name' => 'a.b.c.d.e'], [$record]],
            'a record name too long'           => [['record_name' => str_repeat('a', 64)], [$record]],
            'a record name with a hyphen end'  => [['record_name' => '_sso-'], [$record]],
            'an empty record name'             => [['record_name' => ''], [$record]],
            'a record name that is not text'   => [['record_name' => 42], [$record]],
            'refused domains as a map'         => [['refused' => ['a' => 'example.com']], [$list]],
            'refused domains as a string'      => [['refused' => 'example.com'], [$list]],
            'a refused domain that is not one' => [['refused' => ['example.com', 'not a domain']], ['sso.domains.refused.1 must be a domain name.']],
            'a refused entry that is not text' => [['refused' => [null]], ['sso.domains.refused.0 must be a domain name.']],
            'a pending expiry too short'       => [['pending_expiry_seconds' => 3599], [$pending]],
            'a pending expiry too long'        => [['pending_expiry_seconds' => 2592001], [$pending]],
            'a negative grace period'          => [['recheck_grace_seconds' => -1], [$grace]],
            'a grace period too long'          => [['recheck_grace_seconds' => '2592001'], [$grace]],
            'a linking age above a day'        => [['linking_max_age_seconds' => 86401], [$linking]],
            'a linking age too short'          => [['linking_max_age_seconds' => 59], [$linking]],
            'every problem at once'            => [
                ['record_name' => 'X', 'refused' => 'x', 'pending_expiry_seconds' => 'soon', 'recheck_grace_seconds' => 1.5, 'linking_max_age_seconds' => 0],
                [$record, $list, $pending, $grace, $linking],
            ],
        ];
    }

    /**
     * Each setting reports exactly its problem, every one in a run, and the
     * reader fails closed with the same message.
     *
     * @param  array<string, mixed>  $settings
     * @param  list<string>  $problems
     * @return void
     */
    #[DataProvider('provideSettings')]
    public function testReportsEachProblem(array $settings, array $problems): void
    {
        $this->useThePackage();

        foreach ($settings as $key => $value) {
            config()->set('sso.domains.' . $key, $value);
        }

        self::assertSame($problems, $this->problemsOf(DomainsCheck::class));
    }
}
