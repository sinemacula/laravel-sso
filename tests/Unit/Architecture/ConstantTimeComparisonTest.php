<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;
use Tests\Concerns\ScansLibraryNames;

/**
 * Holds the package to comparing every secret, code (a handoff code above all),
 * state, verifier, token, nonce and digest in constant time (SSO-11.9): only
 * `Secrets\ConstantTime` calls `hash_equals()`, no class calls a string
 * comparison function whose time depends on the bytes compared (`strcmp()` and
 * its kin) but where it compares no secret, and no class compares a value whose
 * name says it is one with `===`, `!==`, `==` or `!=`, unless the other side is
 * `null`, a boolean, a literal or a constant, which only asks whether the value
 * is there. Each exception is listed, with the reason it compares no secret.
 *
 * The testing helpers are left out: they play the identity provider's side, and
 * never compare a value for the package. The source is tokenised, not parsed,
 * and a value is known by the name of the variable, property or method that
 * holds it, so the scan is a backstop for the rule, not a proof of it:
 * `Secrets\ConstantTimeTest` proves the comparison itself.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ConstantTime::class)]
final class ConstantTimeComparisonTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string The name of a value the package compares in constant time. */
    private const string SECRET_NAME = '/(?:digest|secret|verifier|token|nonce|password|challenge|hash|signature|code|state|relaystate)$/i';

    /** @var list<string> The comparison functions whose time depends on the bytes compared, and `hash_equals()`. */
    private const array COMPARISONS = ['hash_equals', 'strcmp', 'strcasecmp', 'strncmp', 'strncasecmp', 'strnatcmp', 'strnatcasecmp', 'substr_compare'];

    /** @var array<string, list<string>> The comparison functions each file may call, in order: the helper itself, and the address policy's prefix match of two packed IP addresses, which are no secret. */
    private const array ALLOWED = [
        'src/Secrets/ConstantTime.php'   => ['hash_equals', 'hash_equals'],
        'src/Fetching/AddressPolicy.php' => ['strncmp'],
    ];

    /** @var array<string, list<string>> The operator comparisons each file may make of a value named as a secret: the log reader's lexer comparing one of its own character tokens with a quote, which is no credential. */
    private const array ALLOWED_OPERATORS = [
        'src/Logging/KeyedValues.php' => ['$token === $quote'],
    ];

    /** @var list<int> The comparison operators. */
    private const array OPERATORS = [T_IS_IDENTICAL, T_IS_NOT_IDENTICAL, T_IS_EQUAL, T_IS_NOT_EQUAL];

    /** @var list<int> The tokens a member chain is made of: a variable, a name, and the operators between them. */
    private const array CHAIN = [T_VARIABLE, T_STRING, T_NAME_QUALIFIED, T_NAME_FULLY_QUALIFIED, T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON];

    /**
     * Rows of `[path]`: every PHP file the package ships but the testing
     * helpers.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSources(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {

            if (str_starts_with($path, 'src/Testing/')) {
                continue;
            }

            yield $path => [$path];
        }
    }

    /**
     * Only `Secrets\ConstantTime` calls `hash_equals()`, and nothing calls a
     * comparison whose time depends on the bytes compared but where the
     * allow-list says it compares no secret.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testOnlyTheHelperCallsAComparisonFunction(string $path): void
    {
        self::assertSame(self::ALLOWED[$path] ?? [], self::comparisonCalls(self::shippedSources()[$path]), "{$path} compares outside Secrets\\ConstantTime.");
    }

    /**
     * No class compares a secret, code, state, verifier, token, nonce or digest
     * with an operator.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNoSecretIsComparedWithAnOperator(string $path): void
    {
        self::assertSame(self::ALLOWED_OPERATORS[$path] ?? [], self::operatorComparisons(self::shippedSources()[$path]), "{$path} compares a secret with an operator.");
    }

    /**
     * Each allow-list names files that exist.
     *
     * @return void
     */
    public function testTheAllowListsNameWhatExists(): void
    {
        foreach ([...array_keys(self::ALLOWED), ...array_keys(self::ALLOWED_OPERATORS)] as $path) {
            self::assertArrayHasKey($path, self::shippedSources());
        }
    }

    /**
     * The scans catch a comparison function, called alone or by its fully
     * qualified name, and a secret compared with each operator, by a variable,
     * a property or a method's name, on either side, a handoff code and an OIDC
     * or SAML state among them; and pass over a check that a value is there, a
     * comparison with a constant or a literal (a status code with a number), a
     * method of a comparison's name, and a value whose name says no secret.
     *
     * @return void
     */
    public function testTheScansTellAComparisonOfASecretFromAnotherCheck(): void
    {
        $source = <<<'PHP'
            <?php
            hash_equals($a, $b);
            \strcmp($a, $b);
            $this->hash_equals($a, $b);
            $locked->claim_token === $claim->token;
            $digest !== $given;
            $value == $this->secret();
            $one != $other->nonce;
            $token === null;
            null !== $verifier;
            $hash === '';
            $state === DomainState::VERIFIED;
            $name === $other->name;
            $given === $row->code;
            $stored->state !== $state;
            $relayState == $expected;
            $status->code === 200;
            PHP;

        self::assertSame(['hash_equals', 'strcmp'], self::comparisonCalls($source));
        self::assertSame([
            '$locked->claim_token === $claim->token',
            '$digest !== $given',
            '$value == $this->secret',
            '$one != $other->nonce',
            '$given === $row->code',
            '$stored->state !== $state',
            '$relayState == $expected',
        ], self::operatorComparisons($source));
    }

    /**
     * The comparison functions the source calls, in order: never a method or a
     * function of the same name being declared.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function comparisonCalls(string $source): array
    {
        $tokens = self::significant($source);
        $found  = [];

        foreach ($tokens as $index => $token) {

            $name = is_array($token) ? strtolower(ltrim($token[1], '\\')) : '';

            if (!in_array($name, self::COMPARISONS, true) || ($tokens[$index + 1] ?? null) !== '(' || self::isMember($tokens[$index - 1] ?? null)) {
                continue;
            }

            $found[] = $name;
        }

        return $found;
    }

    /**
     * The comparisons with an operator the source makes of a value named as a
     * secret, each written as its two operands' chains around the operator,
     * unless the other side is `null`, a boolean, a literal or a constant.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function operatorComparisons(string $source): array
    {
        $tokens = self::significant($source);
        $found  = [];

        foreach ($tokens as $index => $token) {

            if (!is_array($token) || !in_array($token[0], self::OPERATORS, true)) {
                continue;
            }

            $left  = self::chainBefore($tokens, $index);
            $right = self::chainAfter($tokens, $index);

            if (!self::isSecret($left, $right)) {
                continue;
            }

            $found[] = implode('', $left) . ' ' . $token[1] . ' ' . implode('', $right);
        }

        return $found;
    }

    /**
     * Whether one side names a secret and neither is a value that only asks
     * whether the other is there.
     *
     * @param  list<string>  $left
     * @param  list<string>  $right
     * @return bool
     */
    private static function isSecret(array $left, array $right): bool
    {
        if (self::isFixed($left) || self::isFixed($right)) {
            return false;
        }

        return preg_match(self::SECRET_NAME, (string) end($left)) === 1 || preg_match(self::SECRET_NAME, (string) end($right)) === 1;
    }

    /**
     * Whether the chain is a fixed value: empty (a literal, a call's result),
     * `null`, a boolean, or a class constant or enum case.
     *
     * @param  list<string>  $chain
     * @return bool
     */
    private static function isFixed(array $chain): bool
    {
        return $chain === [] || in_array(strtolower($chain[0]), ['null', 'true', 'false'], true) || in_array('::', $chain, true);
    }

    /**
     * The member chain that ends right before the operator, its text in order,
     * a call's arguments left out.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return list<string>
     */
    private static function chainBefore(array $tokens, int $index): array
    {
        $chain = [];
        $index--;

        if (($tokens[$index] ?? null) === ')') {
            $index = self::openingOf($tokens, $index) - 1;
        }

        while (isset($tokens[$index]) && is_array($tokens[$index]) && in_array($tokens[$index][0], self::CHAIN, true)) {
            array_unshift($chain, $tokens[$index][1]);
            $index--;
        }

        return $chain;
    }

    /**
     * The member chain that starts right after the operator, its text in order,
     * up to a call's opening parenthesis.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return list<string>
     */
    private static function chainAfter(array $tokens, int $index): array
    {
        $chain = [];
        $index++;

        while (isset($tokens[$index]) && is_array($tokens[$index]) && in_array($tokens[$index][0], self::CHAIN, true)) {
            $chain[] = $tokens[$index][1];
            $index++;
        }

        return $chain;
    }

    /**
     * The index of the parenthesis that opens the one closing at the index.
     *
     * @param  list<array{0: int, 1: string, 2: int}|string>  $tokens
     * @param  int  $index
     * @return int
     */
    private static function openingOf(array $tokens, int $index): int
    {
        $depth = 0;

        for (; $index >= 0; $index--) {

            $depth += match ($tokens[$index]) {
                ')'     => 1,
                '('     => -1,
                default => 0,
            };

            if ($depth === 0) {
                return $index;
            }
        }

        return 0;
    }

    /**
     * Whether the token before a name makes it a member or a declaration.
     *
     * @param  array{0: int, 1: string, 2: int}|string|null  $previous
     * @return bool
     */
    private static function isMember(array|string|null $previous): bool
    {
        return is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON, T_FUNCTION], true);
    }

    /**
     * The source's tokens without whitespace and comments.
     *
     * @param  string  $source
     * @return list<array{0: int, 1: string, 2: int}|string>
     */
    private static function significant(string $source): array
    {
        return array_values(array_filter(
            token_get_all($source),
            static fn ($token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
    }
}
