<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use SineMacula\Laravel\Sso\Sessions\ProvenanceDomain;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for a session provenance's stored form.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Provenance::class)]
#[CoversClass(ProvenanceDomain::class)]
final class StoredProvenanceTest extends TestCase
{
    use DumpsValues;

    /** @var int The flags the stored form is measured with: JSON's default escaping, a float kept a float. */
    private const int JSON = JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION;

    /**
     * Instants are kept in UTC to the microsecond.
     *
     * @return void
     */
    public function testInstantsAreKeptInUtcToTheMicrosecond(): void
    {
        $provenance = new Provenance(
            'connection-1',
            'tenant-1',
            'oidc',
            CarbonImmutable::parse('2026-11-01T11:29:00.000001+02:00'),
            providerSessionDeadline: CarbonImmutable::parse('2026-11-01T13:00:00.5-05:00'),
            sessionNotAfter: CarbonImmutable::parse('2026-11-01T19:00:00+01:00'),
        );

        self::assertSame(
            ['2026-11-01T09:29:00.000001Z', '2026-11-01T18:00:00.500000Z', '2026-11-01T18:00:00.000000Z'],
            [$provenance->toArray()['provider_auth_time'], $provenance->toArray()['provider_session_deadline'], $provenance->toArray()['session_not_after']],
        );
        self::assertSame(['UTC', 'UTC', 'UTC'], [
            $provenance->providerAuthenticatedAt?->getTimezone()->getName(),
            $provenance->providerSessionDeadline?->getTimezone()->getName(),
            $provenance->sessionNotAfter?->getTimezone()->getName(),
        ]);
    }

    /**
     * Every key is stored, `null` where unstated.
     *
     * @return void
     */
    public function testEveryKeyIsStoredEvenWhenNull(): void
    {
        self::assertSame([
            'version'                          => 1,
            'connection_id'                    => 'connection-1',
            'tenant_id'                        => 'tenant-1',
            'protocol'                         => 'saml2',
            'provider_auth_time'               => null,
            'provider_amr'                     => [],
            'provider_acr'                     => null,
            'provider_authn_context_class_ref' => null,
            'link_id'                          => null,
            'link_provenance'                  => null,
            'provider_session_deadline'        => null,
            'session_not_after'                => null,
            'enforcement_version'              => null,
        ], (new Provenance('connection-1', 'tenant-1', 'saml2'))->toArray());
    }

    /**
     * The stored form restores exactly, even with reordered JSON keys.
     *
     * @return void
     */
    public function testTheStoredFormRestoresExactly(): void
    {
        $stored   = self::full()->toArray();
        $shuffled = array_reverse((array) json_decode((string) json_encode($stored), true), true);
        $restored = Provenance::restore($shuffled);

        self::assertSame($stored, $restored->toArray());
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $restored->linkProvenance);
        self::assertSame('2026-11-01T09:29:00.123456Z', $restored->providerAuthenticatedAt?->format(Provenance::INSTANT_FORMAT));
        self::assertSame(['pwd', 'otp'], $restored->providerMethods());
        self::assertSame('urn:class', $restored->providerAuthnContextClassRef());
    }

    /**
     * A provenance with nothing but what every one has restores exactly.
     *
     * @return void
     */
    public function testTheBarestStoredFormRestoresExactly(): void
    {
        $stored = (new Provenance('connection-1', 'tenant-1', 'oidc'))->toArray();

        self::assertSame($stored, Provenance::restore($stored)->toArray());
    }

    /**
     * A provenance of each protocol with every fact, and one with none.
     *
     * @return iterable<string, array{0: \SineMacula\Laravel\Sso\Sessions\Provenance}>
     */
    public static function provenances(): iterable
    {
        yield 'saml2 with every fact' => [self::full()];
        yield 'oidc with every fact' => [new Provenance(
            'connection-1',
            'tenant-1',
            'oidc',
            CarbonImmutable::parse('2026-11-01T09:29:00.123456Z'),
            ['pwd'],
            'urn:acr',
            null,
            'link-1',
            LinkOrigin::PROVISIONING,
            CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            CarbonImmutable::parse('2026-11-01T17:00:00Z'),
            'enforcement-7',
        )];
        yield 'every optional part null' => [new Provenance('connection-1', 'tenant-1', 'oidc')];
    }

    /**
     * The stored form holds only plain values, so it survives JSON unchanged.
     *
     * @param  \SineMacula\Laravel\Sso\Sessions\Provenance  $provenance
     * @return void
     *
     * @throws \JsonException
     */
    #[DataProvider('provenances')]
    public function testTheStoredFormHoldsOnlyPlainValues(Provenance $provenance): void
    {
        $stored = $provenance->toArray();

        self::assertSame(Provenance::STORED_KEYS, array_keys($stored));
        self::assertSame(Provenance::VERSION, $stored['version']);

        foreach (array_slice($stored, 1) as $key => $value) {

            $plain = $value === null || is_string($value) || (is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value);

            self::assertTrue($plain, "{$key} is not a string, null or a list of strings.");
        }

        $json = json_encode($stored, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION);

        self::assertSame($stored, json_decode($json, true, flags: JSON_THROW_ON_ERROR));
    }

    /**
     * The worst stored form, as default JSON, fits `MAX_STORED_JSON_BYTES`.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWorstStoredFormFitsItsBound(): void
    {
        $stored = self::worst()->toArray();
        $json   = json_encode($stored, self::JSON);

        self::assertSame(3364, strlen($json));
        self::assertLessThanOrEqual(Provenance::MAX_STORED_JSON_BYTES, strlen($json));
        self::assertSame(4096, Provenance::MAX_STORED_JSON_BYTES);
        self::assertSame($stored, json_decode($json, true, flags: JSON_THROW_ON_ERROR));

        foreach (array_slice($stored, 1) as $key => $value) {
            self::assertTrue($value === null || is_string($value) || (is_array($value) && array_is_list($value) && array_filter($value, is_string(...)) === $value), $key);
        }
    }

    /**
     * The worst stored form holds every part at its limit and every key.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testTheWorstStoredFormHoldsEveryPartAtItsLimit(): void
    {
        $stored  = self::worst()->toArray();
        $longest = max(array_map(static fn (LinkOrigin $origin): int => strlen($origin->value), LinkOrigin::cases()));
        $instant = strlen(CarbonImmutable::parse('9999-12-31T23:59:59.999999Z')->format(Provenance::INSTANT_FORMAT));

        self::assertSame(Provenance::STORED_KEYS, array_keys($stored));
        self::assertSame(EvidenceRules::RFC_8176_METHODS, $stored['provider_amr']);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN->value, $stored['link_provenance']);
        self::assertSame(15, $longest);
        self::assertSame(27, $instant);
        self::assertSame([
            'version'                          => 1,
            'connection_id'                    => 2 * Provenance::MAX_CONNECTION_ID_LENGTH + 2,
            'tenant_id'                        => 6 * Provenance::MAX_ID_LENGTH            + 2,
            'protocol'                         => 64                                       + 2,
            'provider_auth_time'               => $instant                                 + 2,
            'provider_amr'                     => strlen(json_encode(EvidenceRules::RFC_8176_METHODS, self::JSON)),
            'provider_acr'                     => 2 * Provenance::MAX_CONTEXT_LENGTH + 2,
            'provider_authn_context_class_ref' => strlen('null'),
            'link_id'                          => 2 * Provenance::MAX_ID_LENGTH      + 2,
            'link_provenance'                  => $longest                           + 2,
            'provider_session_deadline'        => $instant                           + 2,
            'session_not_after'                => $instant                           + 2,
            'enforcement_version'              => 2 * Provenance::MAX_VERSION_LENGTH + 2,
        ], array_map(static fn (mixed $value): int => strlen(json_encode($value, self::JSON)), $stored));
    }

    /**
     * JSON escapes an ASCII byte to at most two bytes, any other to six.
     *
     * @return void
     *
     * @throws \JsonException
     */
    public function testNoByteEscapesToMoreThanTheWorstCaseAssumes(): void
    {
        $printable = 0;
        $any       = 0;

        foreach ([...array_map(chr(...), range(0, 0x7F)), "\u{80}", "\u{7FF}", "\u{800}", "\u{FFFF}", "\u{10000}", "\u{10FFFF}"] as $character) {

            $escaped = (strlen(json_encode($character, self::JSON)) - 2) / strlen($character);
            $any     = max($any, $escaped);

            if (preg_match('/^[\x20-\x7E]$/D', $character) !== 1) {
                continue;
            }

            $printable = max($printable, $escaped);
        }

        self::assertSame([2, 6], [$printable, $any]);
    }

    /**
     * Each way a stored form is not one this version wrote.
     *
     * @return iterable<string, array{0: array<array-key, mixed>}>
     */
    public static function corruptions(): iterable
    {
        $stored = self::full()->toArray();
        $bare   = (new Provenance('connection-1', 'tenant-1', 'oidc'))->toArray();

        yield 'another version' => [array_replace($stored, ['version' => 2])];
        yield 'version zero' => [array_replace($stored, ['version' => 0])];
        yield 'the version as a string' => [array_replace($stored, ['version' => '1'])];
        yield 'the version missing' => [array_diff_key($stored, ['version' => true])];
        yield 'a key missing' => [array_diff_key($stored, ['enforcement_version' => true])];
        yield 'a null key missing' => [array_diff_key($bare, ['link_id' => true])];
        yield 'a key added' => [[...$stored, 'subject' => 'Subject-1 ']];
        yield 'nothing' => [[]];
        yield 'a list' => [array_values($stored)];
        yield 'no connection' => [array_replace($stored, ['connection_id' => null])];
        yield 'an empty connection' => [array_replace($stored, ['connection_id' => ''])];
        yield 'a numeric connection' => [array_replace($stored, ['connection_id' => 7])];
        yield 'no tenant' => [array_replace($stored, ['tenant_id' => null])];
        yield 'no protocol' => [array_replace($stored, ['protocol' => null])];
        yield 'an overlong protocol' => [array_replace($stored, ['protocol' => str_repeat('p', 65)])];
        yield 'a protocol not a driver\'s name' => [array_replace($stored, ['protocol' => 'SAML2'])];
        yield 'an overlong connection' => [array_replace($stored, ['connection_id' => str_repeat('c', 65)])];
        yield 'a tenant not UTF-8' => [array_replace($stored, ['tenant_id' => "tenant-\xFF"])];
        yield 'a method not registered' => [array_replace($stored, ['provider_amr' => ['pwd', 'passkey']])];
        yield 'a method twice' => [array_replace($stored, ['provider_amr' => ['pwd', 'pwd']])];
        yield 'a raw context outside ASCII' => [array_replace($stored, ['provider_authn_context_class_ref' => 'urn:élevé'])];
        yield 'an overlong raw context' => [array_replace($stored, ['provider_authn_context_class_ref' => str_repeat('u', 256)])];
        yield 'a link outside ASCII' => [array_replace($stored, ['link_id' => 'lién'])];
        yield 'an overlong enforcement version' => [array_replace($stored, ['enforcement_version' => str_repeat('v', 65)])];
        yield 'methods as a string' => [array_replace($stored, ['provider_amr' => 'pwd'])];
        yield 'methods as null' => [array_replace($stored, ['provider_amr' => null])];
        yield 'methods keyed' => [array_replace($stored, ['provider_amr' => ['first' => 'pwd']])];
        yield 'a method not a string' => [array_replace($stored, ['provider_amr' => ['pwd', 7]])];
        yield 'an empty method' => [array_replace($stored, ['provider_amr' => ['']])];
        yield 'an acr not a string' => [array_replace($stored, ['provider_acr' => 2])];
        yield 'both raw contexts' => [array_replace($stored, ['provider_acr' => 'urn:acr'])];
        yield 'an empty link' => [array_replace($stored, ['link_id' => ''])];
        yield 'a link provenance with no link' => [array_replace($stored, ['link_id' => null])];
        yield 'an unknown link provenance' => [array_replace($stored, ['link_provenance' => 'invented'])];
        yield 'a link provenance by case' => [array_replace($stored, ['link_provenance' => 'Verified_Domain'])];
        yield 'a numeric link provenance' => [array_replace($stored, ['link_provenance' => 1])];
        yield 'an empty link provenance' => [array_replace($stored, ['link_provenance' => ''])];
        yield 'an instant to the second' => [array_replace($stored, ['provider_auth_time' => '2026-11-01T09:29:00Z'])];
        yield 'an instant with an offset' => [array_replace($stored, ['provider_session_deadline' => '2026-11-01T18:00:00.000000+00:00'])];
        yield 'an instant out of range' => [array_replace($stored, ['session_not_after' => '2026-13-01T17:00:00.000000Z'])];
        yield 'an instant as a number' => [array_replace($stored, ['session_not_after' => 1793552400])];
        yield 'an instant that is not one' => [array_replace($stored, ['provider_auth_time' => 'yesterday'])];
        yield 'an empty enforcement version' => [array_replace($stored, ['enforcement_version' => ''])];
        yield 'an enforcement version not a string' => [array_replace($stored, ['enforcement_version' => 7])];
    }

    /**
     * A stored form this version did not write is refused.
     *
     * @param  array<array-key, mixed>  $stored
     * @return void
     */
    #[DataProvider('corruptions')]
    public function testAStoredFormThisVersionDidNotWriteIsRefused(array $stored): void
    {
        $this->expectExceptionObject(new \UnexpectedValueException('A stored session provenance is not one this version of the package wrote.'));

        Provenance::restore($stored);
    }

    /**
     * Each construction bound with its refusal message, `null` where accepted.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: ?string}>
     */
    public static function bounds(): iterable
    {
        $long    = static fn (int $length): string => str_repeat('a', $length);
        $methods = 'A session provenance keeps a list of RFC 8176\'s registered methods, each at most once.';
        $tenant  = 'A session provenance\'s tenant id is 1 to 255 bytes of UTF-8.';
        $driver  = 'A session provenance\'s protocol is a driver\'s name: a lower-case letter, then up to 63 of them, digits or underscores.';

        yield 'a connection of 64 bytes' => [[$long(64), 't', 'p'], null];
        yield 'a connection of 65 bytes' => [[$long(65), 't', 'p'], self::bytes('connection id', 64, false)];
        yield 'an empty connection' => [['', 't', 'p'], self::bytes('connection id', 64, false)];
        yield 'a connection of every printable character' => [[' ~!"#$%&\'()*+,-./09:;<=>?@AZ[\]^_`az{|}', 't', 'p'], null];
        yield 'a connection with a control character' => [["c\t", 't', 'p'], self::bytes('connection id', 64, false)];
        yield 'a connection with a delete' => [["c\x7F", 't', 'p'], self::bytes('connection id', 64, false)];
        yield 'a connection outside ASCII' => [['connexión', 't', 'p'], self::bytes('connection id', 64, false)];
        yield 'an empty tenant' => [['c', '', 'p'], $tenant];
        yield 'a tenant of 255 bytes' => [['c', $long(255), 'p'], null];
        yield 'a tenant of 256 bytes' => [['c', $long(256), 'p'], $tenant];
        yield 'a tenant outside ASCII' => [['c', 'locataire-é', 'p'], null];
        yield 'a tenant with a control character' => [['c', "tenant\n", 'p'], null];
        yield 'a tenant not UTF-8' => [['c', "tenant-\xFF", 'p'], $tenant];
        yield 'an empty protocol' => [['c', 't', ''], $driver];
        yield 'a protocol of 64 bytes' => [['c', 't', $long(64)], null];
        yield 'a protocol of 65 bytes' => [['c', 't', $long(65)], $driver];
        yield 'a protocol by case' => [['c', 't', 'SAML2'], $driver];
        yield 'a protocol with a hyphen' => [['c', 't', 'ldap-bridge'], $driver];
        yield 'a protocol from a digit' => [['c', 't', '2saml'], $driver];
        yield 'a link of 255 bytes' => [['c', 't', 'p', 'linkId' => $long(255)], null];
        yield 'a link of 256 bytes' => [['c', 't', 'p', 'linkId' => $long(256)], self::bytes('link id', 255, true)];
        yield 'an empty link' => [['c', 't', 'p', 'linkId' => ''], self::bytes('link id', 255, true)];
        yield 'a link outside ASCII' => [['c', 't', 'p', 'linkId' => 'lién'], self::bytes('link id', 255, true)];
        yield 'a version of 64 bytes' => [['c', 't', 'p', 'enforcementVersion' => $long(64)], null];
        yield 'a version of 65 bytes' => [['c', 't', 'p', 'enforcementVersion' => $long(65)], self::bytes('enforcement version', 64, true)];
        yield 'an empty version' => [['c', 't', 'p', 'enforcementVersion' => ''], self::bytes('enforcement version', 64, true)];
        yield 'a version with a control character' => [['c', 't', 'p', 'enforcementVersion' => "v\x00"], self::bytes('enforcement version', 64, true)];
        yield 'an acr of 255 bytes' => [['c', 't', 'p', 'acr' => $long(255)], null];
        yield 'an acr of 256 bytes' => [['c', 't', 'p', 'acr' => $long(256)], self::bytes('acr', 255, true)];
        yield 'an empty acr' => [['c', 't', 'p', 'acr' => ''], self::bytes('acr', 255, true)];
        yield 'an acr outside ASCII' => [['c', 't', 'p', 'acr' => 'urn:élevé'], self::bytes('acr', 255, true)];
        yield 'a class ref of 255 bytes' => [['c', 't', 'p', 'authnContextClassRef' => $long(255)], null];
        yield 'a class ref of 256 bytes' => [['c', 't', 'p', 'authnContextClassRef' => $long(256)], self::bytes('AuthnContextClassRef', 255, true)];
        yield 'a class ref with a control character' => [['c', 't', 'p', 'authnContextClassRef' => "urn:\r"], self::bytes('AuthnContextClassRef', 255, true)];
        yield 'both raw contexts' => [['c', 't', 'p', 'acr' => 'a', 'authnContextClassRef' => 'b'], 'A session provenance states an acr or an AuthnContextClassRef, never both.'];
        yield 'a link provenance with its link' => [['c', 't', 'p', 'linkId' => 'l', 'linkProvenance' => LinkOrigin::MIGRATION], null];
        yield 'a link provenance with no link' => [['c', 't', 'p', 'linkProvenance' => LinkOrigin::MIGRATION], 'A session provenance states a link provenance only with its link.'];
        yield 'a link with no provenance' => [['c', 't', 'p', 'linkId' => 'l'], null];
        yield 'every registered method' => [['c', 't', 'p', 'methods' => EvidenceRules::RFC_8176_METHODS], null];
        yield 'a method twice' => [['c', 't', 'p', 'methods' => ['pwd', 'otp', 'pwd']], $methods];
        yield 'a method not registered' => [['c', 't', 'p', 'methods' => ['pwd', 'passkey']], $methods];
        yield 'a method by case' => [['c', 't', 'p', 'methods' => ['PWD']], $methods];
        yield 'an empty method' => [['c', 't', 'p', 'methods' => ['pwd', '']], $methods];
        yield 'methods keyed' => [['c', 't', 'p', 'methods' => [1 => 'pwd']], $methods];
        yield 'a method not a string' => [['c', 't', 'p', 'methods' => ['pwd', 7]], $methods];
    }

    /**
     * Each bound is accepted or refused exactly at its edge, with its message.
     *
     * @param  array<array-key, mixed>  $arguments
     * @param  ?string  $message
     * @return void
     */
    #[DataProvider('bounds')]
    public function testEachBoundHoldsAtItsEdge(array $arguments, ?string $message): void
    {
        if ($message !== null) {
            $this->expectExceptionObject(new \InvalidArgumentException($message));
        }

        self::assertInstanceOf(Provenance::class, new Provenance(...$arguments)); // @phpstan-ignore argument.type
    }

    /**
     * JSON and dumps show counts and `[redacted]`, never a provider value.
     *
     * @return void
     */
    public function testJsonAndADumpShowNoProviderValue(): void
    {
        $provenance = self::full();
        $expected   = array_replace($provenance->toArray(), ['provider_amr' => 2, 'provider_acr' => null, 'provider_authn_context_class_ref' => '[redacted]']);

        self::assertSame($expected, $provenance->jsonSerialize());
        self::assertSame($expected, $provenance->__debugInfo());

        $oidc     = new Provenance('c', 't', 'oidc', acr: 'urn:secret:acr');
        $redacted = ['provider_amr' => 1, 'provider_acr' => 1, 'provider_authn_context_class_ref' => 1];

        self::assertSame(['provider_amr' => 0, 'provider_acr' => '[redacted]', 'provider_authn_context_class_ref' => null], array_intersect_key($oidc->jsonSerialize(), $redacted));

        $json = (string) json_encode([$provenance, $oidc]);

        foreach ([...array_values(self::dumps($provenance)), ...array_values(self::dumps($oidc)), $json] as $shown) {
            foreach (['pwd', 'otp', 'urn:class', 'urn:secret:acr'] as $value) {
                self::assertStringNotContainsString($value, $shown);
            }
        }
    }

    /**
     * PHP serialisation is refused: only the versioned array is a stable form.
     *
     * @return void
     */
    public function testItCannotBeSerialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A session provenance is stored as its toArray() form, never PHP-serialised.'));

        serialize(self::full());
    }

    /**
     * PHP unserialisation is refused too.
     *
     * @return void
     */
    public function testItCannotBeUnserialized(): void
    {
        $this->expectExceptionObject(new \LogicException('A session provenance is restored from its toArray() form, never PHP-unserialised.'));

        unserialize(sprintf('O:%d:"%s":0:{}', strlen(Provenance::class), Provenance::class));
    }

    /**
     * The message refusing a text outside its bounds.
     *
     * @param  string  $name
     * @param  int  $maxBytes
     * @param  bool  $optional
     * @return string
     */
    private static function bytes(string $name, int $maxBytes, bool $optional): string
    {
        return sprintf('A session provenance\'s %s is 1 to %d bytes of printable ASCII%s.', $name, $maxBytes, $optional ? ' or null' : '');
    }

    /**
     * The provenance whose stored form is largest.
     *
     * @return \SineMacula\Laravel\Sso\Sessions\Provenance
     */
    private static function worst(): Provenance
    {
        $instant = CarbonImmutable::parse('2026-11-01T09:29:00.123456Z');

        return new Provenance(
            str_repeat('"', Provenance::MAX_CONNECTION_ID_LENGTH),
            str_repeat("\x01", Provenance::MAX_ID_LENGTH),
            str_repeat('p', 64),
            $instant,
            EvidenceRules::RFC_8176_METHODS,
            str_repeat('/', Provenance::MAX_CONTEXT_LENGTH),
            null,
            str_repeat('\\', Provenance::MAX_ID_LENGTH),
            LinkOrigin::VERIFIED_DOMAIN,
            $instant,
            $instant,
            str_repeat('/', Provenance::MAX_VERSION_LENGTH),
        );
    }

    /**
     * A provenance with every fact, of a SAML sign-in.
     *
     * @return \SineMacula\Laravel\Sso\Sessions\Provenance
     */
    private static function full(): Provenance
    {
        return new Provenance(
            'connection-1',
            'tenant-1',
            'saml2',
            CarbonImmutable::parse('2026-11-01T09:29:00.123456Z'),
            ['pwd', 'otp'],
            null,
            'urn:class',
            'link-1',
            LinkOrigin::VERIFIED_DOMAIN,
            CarbonImmutable::parse('2026-11-01T18:00:00Z'),
            CarbonImmutable::parse('2026-11-01T17:00:00Z'),
            'enforcement-7',
        );
    }
}
