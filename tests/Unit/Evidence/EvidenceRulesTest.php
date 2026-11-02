<?php

declare(strict_types = 1);

namespace Tests\Unit\Evidence;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Evidence\EvidenceRules;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;

/**
 * Pins what a connection's evidence policy may hold and how it is judged
 * (SSO-8.7): every name by protocol, every bound at, one under and one over,
 * each violation exactly, in order and never echoing a value; a stored policy
 * read by the same rules, malformed being no rules at all; and each combination
 * one value short and exact, with only accepted methods entering what is
 * answered.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EvidenceRules::class)]
final class EvidenceRulesTest extends TestCase
{
    /** @var string The package's OIDC protocol. */
    private const string OIDC = 'oidc';

    /** @var string The package's SAML protocol. */
    private const string SAML = 'saml2';

    /** @var string A driver an application registered. */
    private const string CUSTOM = 'custom';

    /** @var string A class a policy accepts. */
    private const string LOA2 = 'urn:example:loa:2';

    /** @var string Another class a policy accepts. */
    private const string LOA3 = 'urn:example:loa:3';

    /** @var string A class no policy here accepts. */
    private const string UNLISTED = 'urn:example:unlisted';

    /**
     * The registered values are exactly RFC 8176's twenty.
     *
     * @return void
     */
    public function testTheRegisteredMethodsAreRfc8176s(): void
    {
        self::assertSame([
            'face', 'fpt', 'geo', 'hwk', 'iris', 'kba', 'mca', 'mfa', 'otp', 'pin',
            'pwd', 'rba', 'retina', 'sc', 'sms', 'swk', 'tel', 'user', 'vbm', 'wia',
        ], EvidenceRules::RFC_8176_METHODS);
        self::assertSame(32, EvidenceRules::MAX_VALUES);
        self::assertSame(32, EvidenceRules::MAX_COMBINATIONS);
    }

    /**
     * Rows of `[protocol, policy, the violations]`: what a policy may hold.
     *
     * @return iterable<string, array{0: string, 1: array<array-key, mixed>, 2: list<array{0: string, 1: string}>}>
     */
    public static function providePolicies(): iterable
    {
        $combination = ['combinations' => [['amr' => ['pwd']]]];
        $amr         = ['amr' => ['pwd']];
        $counted     = $amr + $combination;
        $classes     = static fn (int $count): array => array_map(static fn (int $index): string => 'urn:example:' . $index, range(1, $count));
        $saml        = ['authn_context_class_ref' => [self::LOA2], 'combinations' => [['authn_context_class_ref' => self::LOA2]]];
        $misplaced   = [['authn_context_class_ref', 'unsupported'], ['combinations.0.authn_context_class_ref', 'unsupported']];
        $first       = ['combinations' => [['authn_context_class_ref' => 'urn:example:1']]];

        yield 'nothing' => [self::OIDC, [], []];
        yield 'nothing over SAML' => [self::SAML, [], []];
        yield 'one method' => [self::OIDC, $counted, []];
        yield 'one class' => [self::OIDC, ['acr' => [self::LOA2], 'combinations' => [['acr' => self::LOA2]]], []];
        yield 'one method and one class' => [self::OIDC, ['amr' => ['pwd'], 'acr' => [self::LOA2], 'combinations' => [['amr' => ['pwd'], 'acr' => self::LOA2]]], []];
        yield 'one SAML class' => [self::SAML, $saml, []];
        yield 'every registered method' => [self::OIDC, ['amr' => EvidenceRules::RFC_8176_METHODS] + $combination, []];
        yield 'a method over a registered driver' => [self::CUSTOM, $counted, []];
        yield 'an empty accepted list beside what counts' => [self::OIDC, ['acr' => []] + $counted, []];

        yield 'an unknown name' => [self::OIDC, ['max_age' => 5] + $counted, [['max_age', 'unknown']]];
        yield 'a number for a name' => [self::OIDC, [3 => 'pwd'] + $counted, [['3', 'unknown']]];
        yield 'a name that cannot be shown' => [self::OIDC, ["bad\x01name" => 'pwd'] + $counted, [['settings', 'unknown']]];
        yield 'a list for a policy' => [self::OIDC, ['pwd'], [['0', 'unknown'], ['combinations', 'required']]];
        yield 'no combinations' => [self::OIDC, $amr, [['combinations', 'required']]];
        yield 'empty combinations' => [self::OIDC, $amr + ['combinations' => []], [['combinations', 'required']]];
        yield 'null combinations' => [self::OIDC, $amr + ['combinations' => null], [['combinations', 'required']]];
        yield 'combinations a string' => [self::OIDC, $amr + ['combinations' => 'pwd'], [['combinations', 'invalid_type']]];
        yield 'combinations a map' => [self::OIDC, $amr + ['combinations' => ['amr' => ['pwd']]], [['combinations', 'invalid_type']]];

        yield 'amr over SAML' => [self::SAML, ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]], [['amr', 'unsupported'], ['combinations.0.amr', 'unsupported']]];
        yield 'acr over SAML' => [self::SAML, ['acr' => [self::LOA2], 'combinations' => [['acr' => self::LOA2]]], [['acr', 'unsupported'], ['combinations.0.acr', 'unsupported']]];
        yield 'a SAML class over OIDC' => [self::OIDC, $saml, $misplaced];
        yield 'a SAML class over a registered driver' => [self::CUSTOM, $saml, $misplaced];

        yield 'amr a string' => [self::OIDC, ['amr' => 'pwd'] + $combination, [['amr', 'invalid_type'], ['combinations.0.amr.0', 'not_allowed']]];
        yield 'amr a map' => [self::OIDC, ['amr' => ['a' => 'pwd']] + $combination, [['amr', 'invalid_type']]];
        yield 'amr holding a number' => [self::OIDC, ['amr' => ['pwd', 1]] + $combination, [['amr.1', 'invalid_type']]];
        yield 'an unregistered method' => [self::OIDC, ['amr' => ['pwd', 'none']] + $combination, [['amr.1', 'not_allowed']]];
        yield 'a method in the wrong case' => [self::OIDC, ['amr' => ['pwd', 'OTP']] + $combination, [['amr.1', 'not_allowed']]];
        yield 'a method twice' => [self::OIDC, ['amr' => ['pwd', 'pwd']] + $combination, [['amr.1', 'duplicate']]];
        yield 'as many methods as may be named, each twice over' => [
            self::OIDC,
            ['amr' => array_fill(0, 32, 'pwd')] + $combination,
            array_map(static fn (int $index): array => ['amr.' . $index, 'duplicate'], range(1, 31)),
        ];
        yield 'one method too many' => [self::OIDC, ['amr' => array_fill(0, 33, 'pwd')] + $combination, [['amr', 'too_many']]];

        yield 'a class list a string' => [
            self::OIDC,
            ['acr' => self::LOA2, 'combinations' => [['acr' => self::LOA2]]],
            [['acr', 'invalid_type'], ['combinations.0.acr', 'not_allowed']],
        ];
        yield 'a class list a map' => [self::OIDC, ['acr' => ['a' => self::LOA2]] + $counted, [['acr', 'invalid_type']]];
        yield 'a class that is no string' => [self::OIDC, ['acr' => [1]] + $counted, [['acr.0', 'invalid_type']]];
        yield 'an empty class' => [self::OIDC, ['acr' => ['']] + $counted, [['acr.0', 'required']]];
        yield 'a class with a control character' => [self::OIDC, ['acr' => ["urn\x01"]] + $counted, [['acr.0', 'invalid_format']]];
        yield 'a class with a space' => [self::OIDC, ['acr' => ['a class']] + $counted, []];
        yield 'a class of one byte' => [self::OIDC, ['acr' => ['c']] + $counted, []];
        yield 'the longest class' => [self::OIDC, ['acr' => [str_repeat('c', 1024)]] + $counted, []];
        yield 'one byte over the longest class' => [self::OIDC, ['acr' => [str_repeat('c', 1025)]] + $counted, [['acr.0', 'too_long']]];
        yield 'a class twice' => [self::OIDC, ['acr' => [self::LOA2, self::LOA3, self::LOA2]] + $counted, [['acr.2', 'duplicate']]];
        yield 'as many classes as may be named' => [self::OIDC, ['acr' => $classes(32)] + $counted, []];
        yield 'one class too many' => [self::OIDC, ['acr' => $classes(33)] + $counted, [['acr', 'too_many']]];
        yield 'as many SAML classes as may be named' => [self::SAML, ['authn_context_class_ref' => $classes(32)] + $first, []];
        yield 'one SAML class too many' => [self::SAML, ['authn_context_class_ref' => $classes(33)] + $first, [['authn_context_class_ref', 'too_many']]];

        yield 'as many combinations as may be named' => [self::OIDC, $amr + ['combinations' => array_fill(0, 32, ['amr' => ['pwd']])], []];
        yield 'one combination too many' => [self::OIDC, $amr + ['combinations' => array_fill(0, 33, ['amr' => ['pwd']])], [['combinations', 'too_many']]];
        yield 'a combination naming nothing' => [self::OIDC, $amr + ['combinations' => [[]]], [['combinations.0', 'required']]];
        yield 'a combination that is a string' => [self::OIDC, $amr + ['combinations' => ['pwd']], [['combinations.0', 'invalid_type']]];
        yield 'a combination that is a list' => [self::OIDC, $amr + ['combinations' => [['pwd']]], [['combinations.0', 'invalid_type']]];
        yield 'a combination naming the unknown' => [self::OIDC, $amr + ['combinations' => [['amr' => ['pwd'], 'nbf' => 1]]], [['combinations.0.nbf', 'unknown']]];
        yield 'a combination with a number for a name' => [self::OIDC, $amr + ['combinations' => [['amr' => ['pwd'], 2 => 1]]], [['combinations.0.2', 'unknown']]];
        yield 'a second combination at fault' => [self::OIDC, $amr + ['combinations' => [['amr' => ['pwd']], []]], [['combinations.1', 'required']]];
        yield 'a combination with no methods' => [self::OIDC, $amr + ['combinations' => [['amr' => []]]], [['combinations.0.amr', 'required']]];
        yield 'a combination with a string for its methods' => [self::OIDC, $amr + ['combinations' => [['amr' => 'pwd']]], [['combinations.0.amr', 'invalid_type']]];
        yield 'a combination with too many methods' => [self::OIDC, $amr + ['combinations' => [['amr' => array_fill(0, 33, 'pwd')]]], [['combinations.0.amr', 'too_many']]];
        yield 'a combination with a method twice' => [self::OIDC, $amr + ['combinations' => [['amr' => ['pwd', 'pwd']]]], [['combinations.0.amr.1', 'duplicate']]];
        yield 'a combination with a method not accepted' => [self::OIDC, $amr + ['combinations' => [['amr' => ['otp']]]], [['combinations.0.amr.0', 'not_allowed']]];
        yield 'a combination when no method is accepted' => [self::OIDC, $combination, [['combinations.0.amr.0', 'not_allowed']]];
        yield 'a combination with a class not accepted' => [
            self::OIDC,
            ['acr' => [self::LOA2], 'combinations' => [['acr' => self::UNLISTED]]],
            [['combinations.0.acr', 'not_allowed']],
        ];
        yield 'a combination with its class a list' => [self::OIDC, ['acr' => [self::LOA2], 'combinations' => [['acr' => [self::LOA2]]]], [['combinations.0.acr', 'invalid_type']]];
        yield 'a combination with a SAML class not accepted' => [
            self::SAML,
            ['authn_context_class_ref' => [self::LOA2], 'combinations' => [['authn_context_class_ref' => self::UNLISTED]]],
            [['combinations.0.authn_context_class_ref', 'not_allowed']],
        ];
        yield 'two unknown names' => [self::OIDC, ['max_age' => 5, 'nbf' => 6] + $counted, [['max_age', 'unknown'], ['nbf', 'unknown']]];
        yield 'two classes at fault' => [self::OIDC, ['acr' => [1, '']] + $counted, [['acr.0', 'invalid_type'], ['acr.1', 'required']]];
        yield 'the same class at fault twice' => [self::OIDC, ['acr' => [1, 1]] + $counted, [['acr.0', 'invalid_type'], ['acr.1', 'invalid_type']]];
        yield 'two combinations at fault' => [self::OIDC, $amr + ['combinations' => [[], 'pwd']], [['combinations.0', 'required'], ['combinations.1', 'invalid_type']]];
        yield 'a combination with two parts at fault' => [
            self::OIDC,
            $amr + ['combinations' => [['amr' => [], 'nbf' => 1]]],
            [['combinations.0.amr', 'required'], ['combinations.0.nbf', 'unknown']],
        ];
        yield 'everything in its order' => [
            self::OIDC,
            ['combinations' => [[]], 'acr' => 1, 'amr' => 2, 'other' => 3],
            [['other', 'unknown'], ['amr', 'invalid_type'], ['acr', 'invalid_type'], ['combinations.0', 'required']],
        ];
    }

    /**
     * A policy is judged exactly, the same whichever way it is met: a policy
     * with no violation reads as rules when it holds anything, and one with any
     * reads as none.
     *
     * @param  string  $protocol
     * @param  array<array-key, mixed>  $policy
     * @param  list<array{0: string, 1: string}>  $violations
     * @return void
     */
    #[DataProvider('providePolicies')]
    public function testAPolicyIsJudged(string $protocol, array $policy, array $violations): void
    {
        $found = array_map(static fn (SettingViolation $violation): array => [$violation->setting, $violation->code->value], EvidenceRules::violations($policy, $protocol));

        self::assertSame($violations, $found);
        self::assertSame($violations === [] && $policy !== [], EvidenceRules::parse($policy, $protocol) !== null);
    }

    /**
     * A violation never echoes what was given, as a value or as a part of one.
     *
     * @return void
     */
    public function testAViolationNeverEchoesAValue(): void
    {
        $secret = 'urn:example:the-accepted-class';
        $found  = EvidenceRules::violations([
            'acr'          => [$secret . "\x01", $secret . "\x01"],
            'amr'          => [$secret],
            'combinations' => [['acr' => $secret, 'amr' => [$secret]]],
        ], self::OIDC);

        self::assertNotSame([], $found);
        self::assertStringNotContainsString($secret, (string) json_encode($found));
    }

    /**
     * Rows of what is stored that is no policy: none reads as rules.
     *
     * @return iterable<string, array{0: mixed}>
     */
    public static function provideNonPolicies(): iterable
    {
        yield 'nothing' => [null];
        yield 'empty' => [[]];
        yield 'a number' => [5];
        yield 'a string' => ['amr'];
        yield 'true' => [true];
        yield 'no combinations' => [['amr' => ['pwd']]];
        yield 'a combination naming nothing' => [['amr' => ['pwd'], 'combinations' => [[]]]];
        yield 'an unlisted method in a combination' => [['amr' => ['pwd'], 'combinations' => [['amr' => ['otp']]]]];
        yield 'an unregistered method' => [['amr' => ['custom'], 'combinations' => [['amr' => ['custom']]]]];
        yield 'an unknown name beside what counts' => [['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]], 'other' => 1]];
    }

    /**
     * What is stored that is no policy reads as no rules, not an exception.
     *
     * @param  mixed  $stored
     * @return void
     */
    #[DataProvider('provideNonPolicies')]
    public function testWhatIsNoPolicyReadsAsNoRules(mixed $stored): void
    {
        self::assertNull(EvidenceRules::parse($stored, self::OIDC));
    }

    /**
     * A stored policy reads by the protocol it is read for: one protocol's
     * names are malformed on another.
     *
     * @return void
     */
    public function testAStoredPolicyIsReadForItsProtocol(): void
    {
        $oidc = ['amr' => ['pwd'], 'combinations' => [['amr' => ['pwd']]]];
        $saml = ['authn_context_class_ref' => [self::LOA2], 'combinations' => [['authn_context_class_ref' => self::LOA2]]];

        self::assertNotNull(EvidenceRules::parse($oidc, self::OIDC));
        self::assertNull(EvidenceRules::parse($oidc, self::SAML));
        self::assertNotNull(EvidenceRules::parse($saml, self::SAML));
        self::assertNull(EvidenceRules::parse($saml, self::OIDC));
    }

    /**
     * Rows of `[accepted, combinations, the methods and class stated, what is
     * answered]`: each combination rule, one value short and exact; only
     * accepted methods entering, in their asserted order and each once.
     *
     * @return iterable<string, array{0: list<string>, 1: list<array<string, list<string>|string>>, 2: list<string>, 3: ?string, 4: ?list<string>}>
     */
    public static function provideContexts(): iterable
    {
        $two     = [['amr' => ['pwd', 'otp']]];
        $pair    = [['amr' => ['pwd'], 'acr' => self::LOA2]];
        $class   = [['acr' => self::LOA2]];
        $either  = [['amr' => ['hwk']], ['acr' => self::LOA3], ['amr' => ['pwd', 'otp'], 'acr' => self::LOA2]];
        $methods = ['pwd', 'otp', 'hwk'];

        yield 'one method: stated' => [['pwd'], [['amr' => ['pwd']]], ['pwd'], null, ['pwd']];
        yield 'one method: another stated' => [['pwd'], [['amr' => ['pwd']]], ['otp'], null, null];
        yield 'one method: none stated' => [['pwd'], [['amr' => ['pwd']]], [], null, null];
        yield 'one method: another case' => [['pwd'], [['amr' => ['pwd']]], ['PWD'], null, null];
        yield 'two methods: exact' => [$methods, $two, ['pwd', 'otp'], null, ['pwd', 'otp']];
        yield 'two methods: the first short' => [$methods, $two, ['otp'], null, null];
        yield 'two methods: the second short' => [$methods, $two, ['pwd'], null, null];
        yield 'two methods: and another accepted' => [$methods, $two, ['pwd', 'otp', 'hwk'], null, ['pwd', 'otp', 'hwk']];
        yield 'two methods: one replaced by another accepted' => [$methods, $two, ['pwd', 'hwk'], null, null];
        yield 'partly listed: only the accepted enter' => [['pwd'], [['amr' => ['pwd']]], ['sms', 'pwd', 'custom'], null, ['pwd']];
        yield 'partly listed: a method accepted and not asked for enters' => [['pwd', 'otp'], [['amr' => ['pwd']]], ['pwd', 'sms', 'otp'], null, ['pwd', 'otp']];
        yield 'partly listed: what is unlisted completes nothing' => [['pwd'], [['amr' => ['pwd']]], ['sms'], null, null];
        yield 'in asserted order' => [$methods, $two, ['otp', 'hwk', 'pwd'], null, ['otp', 'hwk', 'pwd']];
        yield 'each once' => [$methods, $two, ['pwd', 'otp', 'pwd'], null, ['pwd', 'otp']];
        yield 'a class: stated' => [[], $class, [], self::LOA2, []];
        yield 'a class: another stated' => [[], $class, [], self::UNLISTED, null];
        yield 'a class: none stated' => [[], $class, [], null, null];
        yield 'a class: another case' => [[], $class, [], strtoupper(self::LOA2), null];
        yield 'a class: a method says nothing of it' => [['pwd'], $class, ['pwd'], null, null];
        yield 'a class: methods accepted enter too' => [['pwd'], $class, ['pwd'], self::LOA2, ['pwd']];
        yield 'a pair: exact' => [['pwd'], $pair, ['pwd'], self::LOA2, ['pwd']];
        yield 'a pair: the method short' => [['pwd'], $pair, [], self::LOA2, null];
        yield 'a pair: the class short' => [['pwd'], $pair, ['pwd'], null, null];
        yield 'a pair: another class' => [['pwd'], $pair, ['pwd'], self::UNLISTED, null];
        yield 'any: none' => [$methods, $either, ['pwd'], self::LOA2, null];
        yield 'any: the first' => [$methods, $either, ['hwk'], null, ['hwk']];
        yield 'any: the second' => [$methods, $either, [], self::LOA3, []];
        yield 'any: the last' => [$methods, $either, ['otp', 'pwd'], self::LOA2, ['otp', 'pwd']];
    }

    /**
     * What a policy answers of a context.
     *
     * @param  list<string>  $amr
     * @param  list<array<string, list<string>|string>>  $combinations
     * @param  list<string>  $methods
     * @param  ?string  $class
     * @param  ?list<string>  $expected
     * @return void
     */
    #[DataProvider('provideContexts')]
    public function testAContextIsJudged(array $amr, array $combinations, array $methods, ?string $class, ?array $expected): void
    {
        $rules = EvidenceRules::parse(['amr' => $amr, 'acr' => [self::LOA2, self::LOA3], 'combinations' => $combinations], self::OIDC);

        self::assertNotNull($rules);
        self::assertSame($expected, $rules->acceptedMethods(new AuthenticationContext(methods: $methods, contextClass: $class)));
    }

    /**
     * On SAML only the class counts, and no method is ever answered.
     *
     * @return void
     */
    public function testASamlClassIsJudged(): void
    {
        $rules = EvidenceRules::parse(['authn_context_class_ref' => [self::LOA2, self::LOA3], 'combinations' => [['authn_context_class_ref' => self::LOA3]]], self::SAML);

        self::assertNotNull($rules);
        self::assertSame([], $rules->acceptedMethods(new AuthenticationContext(contextClass: self::LOA3)));
        self::assertSame([], $rules->acceptedMethods(new AuthenticationContext(methods: ['pwd'], contextClass: self::LOA3)));
        self::assertNull($rules->acceptedMethods(new AuthenticationContext(contextClass: self::LOA2)));
        self::assertNull($rules->acceptedMethods(new AuthenticationContext(contextClass: self::UNLISTED)));
        self::assertNull($rules->acceptedMethods(new AuthenticationContext));
    }
}
