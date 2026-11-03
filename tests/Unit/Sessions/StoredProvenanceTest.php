<?php

declare(strict_types = 1);

namespace Tests\Unit\Sessions;

use Carbon\CarbonImmutable;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Sessions\Provenance;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests for a session provenance's stored form (SSO-9.7, SSO-9.10): UTC
 * instants to the microsecond, every key present with `null` where unstated,
 * the versioned form restored exactly (in any key order, as a database's JSON
 * column may give it back), every refusal of a form this version did not write,
 * each bound of a construction at its edge, and that no dump, JSON or PHP
 * serialisation shows a provider value.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Provenance::class)]
final class StoredProvenanceTest extends TestCase
{
    use DumpsValues;

    /**
     * Instants are kept in UTC to the microsecond, whatever zone they were
     * given in, and the effective cap is kept to whatever precision it has.
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
     * A provenance with only what every one has stores every key, `null` and no
     * methods for the rest.
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
     * The stored form restores exactly, including through JSON with its keys in
     * another order, as a database's JSON column may give them back.
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
        yield 'an overlong protocol' => [array_replace($stored, ['protocol' => str_repeat('p', 256)])];
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
     * A stored form this version did not write is refused, never read as
     * something else.
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
     * Each bound of a construction, by its arguments, and the message of its
     * refusal; `null` where it is accepted.
     *
     * @return iterable<string, array{0: array<array-key, mixed>, 1: ?string}>
     */
    public static function bounds(): iterable
    {
        $long    = static fn (int $length): string => str_repeat('a', $length);
        $methods = 'A session provenance keeps a list of at most 32 methods of 1 to 255 bytes.';

        yield 'a connection of 255 bytes' => [[$long(255), 't', 'p'], null];
        yield 'a connection of 256 bytes' => [[$long(256), 't', 'p'], self::bytes('connection id', 255, false)];
        yield 'an empty connection' => [['', 't', 'p'], self::bytes('connection id', 255, false)];
        yield 'an empty tenant' => [['c', '', 'p'], self::bytes('tenant id', 255, false)];
        yield 'a tenant of 256 bytes' => [['c', $long(256), 'p'], self::bytes('tenant id', 255, false)];
        yield 'an empty protocol' => [['c', 't', ''], self::bytes('protocol', 255, false)];
        yield 'a protocol of 255 bytes' => [['c', 't', $long(255)], null];
        yield 'a link of 255 bytes' => [['c', 't', 'p', 'linkId' => $long(255)], null];
        yield 'a link of 256 bytes' => [['c', 't', 'p', 'linkId' => $long(256)], self::bytes('link id', 255, true)];
        yield 'an empty link' => [['c', 't', 'p', 'linkId' => ''], self::bytes('link id', 255, true)];
        yield 'a version of 255 bytes' => [['c', 't', 'p', 'enforcementVersion' => $long(255)], null];
        yield 'a version of 256 bytes' => [['c', 't', 'p', 'enforcementVersion' => $long(256)], self::bytes('enforcement version', 255, true)];
        yield 'an empty version' => [['c', 't', 'p', 'enforcementVersion' => ''], self::bytes('enforcement version', 255, true)];
        yield 'an acr of 1024 bytes' => [['c', 't', 'p', 'acr' => $long(1024)], null];
        yield 'an acr of 1025 bytes' => [['c', 't', 'p', 'acr' => $long(1025)], self::bytes('acr', 1024, true)];
        yield 'an empty acr' => [['c', 't', 'p', 'acr' => ''], self::bytes('acr', 1024, true)];
        yield 'a class ref of 1024 bytes' => [['c', 't', 'p', 'authnContextClassRef' => $long(1024)], null];
        yield 'a class ref of 1025 bytes' => [['c', 't', 'p', 'authnContextClassRef' => $long(1025)], self::bytes('AuthnContextClassRef', 1024, true)];
        yield 'both raw contexts' => [['c', 't', 'p', 'acr' => 'a', 'authnContextClassRef' => 'b'], 'A session provenance states an acr or an AuthnContextClassRef, never both.'];
        yield 'a link provenance with its link' => [['c', 't', 'p', 'linkId' => 'l', 'linkProvenance' => LinkOrigin::MIGRATION], null];
        yield 'a link provenance with no link' => [['c', 't', 'p', 'linkProvenance' => LinkOrigin::MIGRATION], 'A session provenance states a link provenance only with its link.'];
        yield 'a link with no provenance' => [['c', 't', 'p', 'linkId' => 'l'], null];
        yield '32 methods' => [['c', 't', 'p', 'methods' => array_fill(0, 32, 'pwd')], null];
        yield '33 methods' => [['c', 't', 'p', 'methods' => array_fill(0, 33, 'pwd')], $methods];
        yield 'a method of 255 bytes' => [['c', 't', 'p', 'methods' => [$long(255)]], null];
        yield 'a method of 256 bytes' => [['c', 't', 'p', 'methods' => [$long(256)]], $methods];
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
     * `json_encode()` and a dump show the methods as a count and each raw
     * context as `[redacted]`, never a value the provider asserted.
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
        return sprintf('A session provenance\'s %s is 1 to %d bytes%s.', $name, $maxBytes, $optional ? ' or null' : '');
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
