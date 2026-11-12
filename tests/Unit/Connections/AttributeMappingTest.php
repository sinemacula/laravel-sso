<?php

declare(strict_types = 1);

namespace Tests\Unit\Connections;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\AttributeMapping;
use SineMacula\Laravel\Sso\Connections\MappingLimits;
use SineMacula\Laravel\Sso\Connections\SettingViolation;

/**
 * Unit tests for a connection's attribute mapping.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(AttributeMapping::class)]
final class AttributeMappingTest extends TestCase
{
    /** @var list<string> The custom keys the application these tests stand for declares. */
    private const array DECLARED = ['department', 'cost_center_2', 'roles', 'notes'];

    /**
     * OIDC and SAML have default mappings; other protocols have none.
     *
     * @return void
     */
    public function testHasDefaultsForEachPackageProtocol(): void
    {
        self::assertSame([
            'email'        => 'email',
            'given_name'   => 'given_name',
            'family_name'  => 'family_name',
            'display_name' => 'name',
            'groups'       => 'groups',
        ], AttributeMapping::defaults('oidc'));

        self::assertSame([
            'email'        => 'urn:oid:0.9.2342.19200300.100.1.3',
            'given_name'   => 'urn:oid:2.5.4.42',
            'family_name'  => 'urn:oid:2.5.4.4',
            'display_name' => 'urn:oid:2.16.840.1.113730.3.1.241',
            'groups'       => 'urn:oid:1.3.6.1.4.1.5923.1.5.1.1',
        ], AttributeMapping::defaults('saml2'));

        self::assertSame([], AttributeMapping::defaults('example'));

        foreach (['oidc', 'saml2'] as $protocol) {
            self::assertSame([], AttributeMapping::fromArray($protocol, AttributeMapping::defaults($protocol), self::limits())->violations(), $protocol);
        }
    }

    /**
     * The mapping is stored as given, target by target.
     *
     * @return void
     */
    public function testStoresTheMappingAsGiven(): void
    {
        $mapping = ['email' => 'mail', 'department' => 'dept', 'groups' => 'memberOf'];

        self::assertSame($mapping, AttributeMapping::fromArray('saml2', $mapping, self::limits())->toArray());
    }

    /**
     * Rows of `[protocol, mapping, violations]`, each `[setting, code]`.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>, 2: list<array{0: string, 1: string}>}>
     */
    public static function provideViolations(): iterable
    {
        yield from [
            'a custom target'                => ['oidc', ['department' => 'department', 'cost_center_2' => 'cc'], []],
            'an upper-case target'           => ['oidc', ['Department' => 'department'], [['attribute_mapping.Department', 'invalid_format']]],
            'a target starting with a digit' => ['oidc', ['2fa' => 'amr_value'], [['attribute_mapping.2fa', 'invalid_format']]],
            'a target with a hyphen'         => ['oidc', ['cost-center' => 'cc'], [['attribute_mapping.cost-center', 'invalid_format']]],
            'an overlong target'             => ['oidc', [str_repeat('a', 65) => 'x'], [['attribute_mapping.' . str_repeat('a', 65), 'invalid_format']]],
            'a numbered target'              => ['oidc', ['email'], [['attribute_mapping.0', 'invalid_format']]],
            'an empty target'                => ['oidc', ['' => 'email'], [['attribute_mapping', 'invalid_format']]],
            'a source that is not a string'  => ['oidc', ['email' => ['email']], [['attribute_mapping.email', 'invalid_type']]],
            'a null source'                  => ['oidc', ['email' => null], [['attribute_mapping.email', 'invalid_type']]],
            'an empty source'                => ['saml2', ['email' => ''], [['attribute_mapping.email', 'required']]],
            'an overlong source'             => ['saml2', ['email' => str_repeat('s', 1025)], [['attribute_mapping.email', 'too_long']]],
            'a source with a control'        => ['saml2', ['email' => "mail\n"], [['attribute_mapping.email', 'invalid_format']]],
            'a source of most length'        => ['saml2', ['email' => str_repeat('s', 1024)], []],
            'a protocol value under saml'    => ['saml2', ['department' => 'sub'], []],
            'a bad target and source'        => ['saml2', ['Bad' => ''], [['attribute_mapping.Bad', 'invalid_format']]],
            'several, in the order given'    => [
                'oidc',
                ['subject' => 'sub', 'email' => '', 'department' => 'id_token', 'Bad' => 'x'],
                [
                    ['attribute_mapping.subject', 'reserved'],
                    ['attribute_mapping.email', 'required'],
                    ['attribute_mapping.department', 'reserved'],
                    ['attribute_mapping.Bad', 'invalid_format'],
                ],
            ],
        ];
    }

    /**
     * Each refused target or source is reported at its target, unechoed.
     *
     * @param  string  $protocol
     * @param  array<array-key, mixed>  $mapping
     * @param  list<array{0: string, 1: string}>  $expected
     * @return void
     */
    #[DataProvider('provideViolations')]
    public function testReportsEachViolationAtItsTarget(string $protocol, array $mapping, array $expected): void
    {
        self::assertSame($expected, self::violationsOf(AttributeMapping::fromArray($protocol, $mapping, self::limits())));
    }

    /**
     * Rows of `[target]`: each of the result's own fields.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedTargets(): iterable
    {
        foreach (AttributeMapping::RESERVED_TARGETS as $target) {
            yield $target => [$target];
        }
    }

    /**
     * A mapping never targets one of the result's own fields.
     *
     * @param  string  $target
     * @return void
     */
    #[DataProvider('provideReservedTargets')]
    public function testRefusesAReservedTarget(string $target): void
    {
        foreach (['oidc', 'saml2', 'example'] as $protocol) {
            self::assertSame([['attribute_mapping.' . $target, 'reserved']], self::violationsOf(AttributeMapping::fromArray($protocol, [$target => 'value'], self::limits())));
        }
    }

    /**
     * The reserved targets are the result's fields the specification names.
     *
     * @return void
     */
    public function testReservesTheResultsOwnFields(): void
    {
        self::assertSame([
            'issuer', 'subject', 'name_id', 'name_id_format', 'connection', 'connection_id', 'tenant', 'tenant_id', 'protocol', 'application', 'purpose',
            'authentication_context', 'auth_time', 'amr', 'acr', 'session', 'session_id', 'sid', 'session_index', 'email_verified', 'domain_verified',
            'identity', 'identity_id', 'reference', 'linking_email',
        ], AttributeMapping::RESERVED_TARGETS);

        self::assertSame([
            'iss', 'sub', 'aud', 'exp', 'iat', 'nbf', 'jti', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'at_hash', 'c_hash', 's_hash', 'sid', 'email_verified',
            'access_token', 'id_token', 'refresh_token', 'code', 'state', 'client_id',
        ], AttributeMapping::RESERVED_OIDC_SOURCES);
    }

    /**
     * Rows of `[source]`: each OIDC protocol value or token.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideReservedSources(): iterable
    {
        foreach (AttributeMapping::RESERVED_OIDC_SOURCES as $source) {
            yield $source => [$source];
        }
    }

    /**
     * Over OIDC no target reads a protocol value or token; over SAML it may.
     *
     * @param  string  $source
     * @return void
     */
    #[DataProvider('provideReservedSources')]
    public function testRefusesAnOidcProtocolValueOrTokenAsASource(string $source): void
    {
        $mapping = ['email' => $source, 'department' => $source];

        self::assertSame(
            [['attribute_mapping.email', 'reserved'], ['attribute_mapping.department', 'reserved']],
            self::violationsOf(AttributeMapping::fromArray('oidc', $mapping, self::limits())),
        );
        self::assertSame([], self::violationsOf(AttributeMapping::fromArray('saml2', $mapping, self::limits())));
    }

    /**
     * An undeclared custom target is `not_allowed` before its source is judged.
     *
     * @return void
     */
    public function testRefusesACustomTargetTheApplicationDoesNotDeclare(): void
    {
        $mapping = AttributeMapping::defaults('oidc') + ['department' => 'dept', 'badge' => 'badge', 'locker' => '', 'Bad' => 'x'];

        self::assertSame(
            [['attribute_mapping.badge', 'not_allowed'], ['attribute_mapping.locker', 'not_allowed'], ['attribute_mapping.Bad', 'invalid_format']],
            self::violationsOf(AttributeMapping::fromArray('oidc', $mapping, self::limits())),
        );
        self::assertSame(
            [['attribute_mapping.department', 'not_allowed']],
            self::violationsOf(AttributeMapping::fromArray('oidc', AttributeMapping::defaults('oidc') + ['department' => 'dept'], self::limits(['custom_attributes' => []]))),
        );
        self::assertSame([], self::violationsOf(AttributeMapping::fromArray('saml2', AttributeMapping::defaults('saml2'), self::limits(['custom_attributes' => []]))));
    }

    /**
     * A custom target's form: well formed, and neither standard nor reserved.
     *
     * @return void
     */
    public function testTellsACustomTargetsForm(): void
    {
        foreach (['department', 'a', 'a' . str_repeat('b', 63), 'cost_center_2'] as $target) {
            self::assertTrue(AttributeMapping::isCustomTarget($target), $target);
        }

        foreach (['email', 'groups', 'tenant_id', 'subject', 'Department', '2fa', 'cost-center', '', 'a' . str_repeat('b', 64)] as $target) {
            self::assertFalse(AttributeMapping::isCustomTarget($target), $target);
        }
    }

    /**
     * A malformed custom key declaration fails closed, naming its key.
     *
     * @return void
     */
    public function testAMalformedDeclarationFailsClosed(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', [], self::limits(['custom_attributes' => ['email']]));

        foreach ([$mapping->violations(...), static fn (): array => $mapping->map([])] as $read) {
            try {
                $read();
                self::fail('A malformed declaration was read.');
            } catch (\InvalidArgumentException $exception) {
                self::assertStringStartsWith('sso.mapping.custom_attributes must be a list of at most 100 distinct custom keys', $exception->getMessage());
            }
        }
    }

    /**
     * Single-valued targets take the value or the first string of a list.
     *
     * @return void
     */
    public function testMapsTheStandardTargetsToOneValue(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', AttributeMapping::defaults('oidc'), self::limits());

        self::assertSame([
            'email'       => 'ada@example.com',
            'given_name'  => 'Ada',
            'family_name' => 'Lovelace',
        ], $mapping->map([
            'email'       => 'ada@example.com',
            'given_name'  => [1, 'Ada', 'Augusta'],
            'family_name' => ['Lovelace'],
            'name'        => [true, 2.5],
            'unmapped'    => 'ignored',
        ]));
    }

    /**
     * Groups map to a capped list of strings, in order.
     *
     * @return void
     */
    public function testMapsGroupsToAList(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', ['groups' => 'groups'], self::limits(['max_values' => 3]));

        self::assertSame(['groups' => ['admins']], $mapping->map(['groups' => 'admins']));
        self::assertSame(['groups' => ['b', 'a', 'admins']], $mapping->map(['groups' => ['b', 7, 'a', ['nested'], 'admins', 'd', 'e']]));
        self::assertSame(['groups' => ['x']], $mapping->map(['groups' => ['key' => 'x']]));
        self::assertSame([], $mapping->map(['groups' => [1, 2]]));
        self::assertSame([], $mapping->map(['groups' => null]));
        self::assertSame([], $mapping->map([]));
    }

    /**
     * A custom target keeps a string, or a list of at most the cap.
     *
     * @return void
     */
    public function testMapsACustomTargetToAStringOrAList(): void
    {
        $mapping = AttributeMapping::fromArray('saml2', ['department' => 'dept', 'roles' => 'role'], self::limits(['max_values' => 2]));

        self::assertSame(['department' => 'Engineering', 'roles' => ['a', 'b']], $mapping->map(['dept' => 'Engineering', 'role' => ['a', false, 'b', 'c']]));
        self::assertSame(['department' => ['Engineering']], $mapping->map(['dept' => ['Engineering']]));
        self::assertSame([], $mapping->map(['dept' => 42, 'role' => []]));
    }

    /**
     * Every string is cut to the cap in characters, never splitting one.
     *
     * @return void
     */
    public function testCutsEveryValueToTheCap(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', ['display_name' => 'name', 'groups' => 'groups', 'notes' => 'notes'], self::limits(['max_value_length' => 64]));
        $mapped  = $mapping->map([
            'name'   => str_repeat('é', 70),
            'groups' => [str_repeat('g', 65)],
            'notes'  => str_repeat('n', 64),
        ]);

        self::assertSame(str_repeat('é', 64), $mapped['display_name']);
        self::assertSame([str_repeat('g', 64)], $mapped['groups']);
        self::assertSame(str_repeat('n', 64), $mapped['notes']);
    }

    /**
     * A stored custom target the application no longer declares maps nothing.
     *
     * @return void
     */
    public function testNeverMapsACustomTargetNoLongerDeclared(): void
    {
        $stored = ['email' => 'email', 'department' => 'dept', 'roles' => 'role'];
        $values = ['email' => 'ada@example.com', 'dept' => 'Engineering', 'role' => 'admin'];

        self::assertSame(
            ['email' => 'ada@example.com', 'department' => 'Engineering', 'roles' => 'admin'],
            AttributeMapping::fromArray('oidc', $stored, self::limits())->map($values),
        );
        self::assertSame(
            ['email' => 'ada@example.com', 'roles' => 'admin'],
            AttributeMapping::fromArray('oidc', $stored, self::limits(['custom_attributes' => ['roles']]))->map($values),
        );
    }

    /**
     * A target that could never be stored is never mapped.
     *
     * @return void
     */
    public function testNeverMapsARefusedTargetOrSource(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', ['subject' => 'sub', 'Bad' => 'x', 'email' => ['email']], self::limits());

        self::assertSame([], $mapping->map(['sub' => 'abc', 'x' => 'y', 'email' => 'ada@example.com']));
    }

    /**
     * An unmappable target is skipped and the rest still map.
     *
     * @return void
     */
    public function testSkipsWhatItCannotMapAndMapsTheRest(): void
    {
        $mapping = AttributeMapping::fromArray('oidc', ['Bad' => 'x', 'notes' => 'missing', 'department' => 'dept', 0 => 'email', 'email' => 'email'], self::limits());

        set_error_handler(static function (int $severity, string $message): never {
            throw new \ErrorException($message, 0, $severity);
        });

        try {
            $mapped = $mapping->map(['x' => 'y', 'dept' => 42, 'email' => 'ada@example.com']);
        } finally {
            restore_error_handler();
        }

        self::assertSame(['email' => 'ada@example.com'], $mapped);
    }

    /**
     * Mapping limits declaring `DECLARED` unless the settings declare others.
     *
     * @param  array<string, mixed>  $mapping
     * @return \SineMacula\Laravel\Sso\Connections\MappingLimits
     */
    private static function limits(array $mapping = []): MappingLimits
    {
        return new MappingLimits(new Repository(['sso' => ['mapping' => $mapping + ['custom_attributes' => self::DECLARED]]]));
    }

    /**
     * Each violation as `[setting, code]`.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\AttributeMapping  $mapping
     * @return list<array{0: string, 1: string}>
     */
    private static function violationsOf(AttributeMapping $mapping): array
    {
        return array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], $mapping->violations());
    }
}
