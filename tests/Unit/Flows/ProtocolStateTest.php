<?php

declare(strict_types = 1);

namespace Tests\Unit\Flows;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\ProtocolState;
use Symfony\Component\VarDumper\Cloner\VarCloner;
use Symfony\Component\VarDumper\Dumper\CliDumper;

/**
 * Unit tests for an authorisation request's protocol state.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProtocolState::class)]
final class ProtocolStateTest extends TestCase
{
    /** @var string A value: exactly 43 base64url characters. */
    private const string VALUE = '/^[A-Za-z0-9_-]{43}$/D';

    /**
     * Each value is 43 base64url characters, and the three differ.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachValueIsFortyThreeBase64UrlCharacters(): void
    {
        $state = ProtocolState::generate();

        $values = [$state->state()->reveal(), $state->nonce()->reveal(), $state->codeVerifier()->reveal()];

        foreach ($values as $value) {
            self::assertMatchesRegularExpression(self::VALUE, $value);
            self::assertSame(ProtocolState::LENGTH, strlen($value));
        }

        self::assertSame(43, ProtocolState::LENGTH);
        self::assertCount(3, array_unique($values));
    }

    /**
     * Each generation is new: no value repeats across many.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEveryGenerationIsNew(): void
    {
        $values = [];

        for ($generation = 0; $generation < 50; $generation++) {

            $state = ProtocolState::generate();

            $values[] = $state->state()->reveal();
            $values[] = $state->nonce()->reveal();
            $values[] = $state->codeVerifier()->reveal();
        }

        self::assertCount(150, array_unique($values));
    }

    /**
     * Each value decodes to 32 bytes: 256 bits.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testEachValueIsThirtyTwoRandomBytes(): void
    {
        $state = ProtocolState::generate();

        foreach ([$state->state(), $state->nonce(), $state->codeVerifier()] as $secret) {
            self::assertSame(32, strlen((string) base64_decode(strtr($secret->reveal(), '-_', '+/'), true)));
        }
    }

    /**
     * The digests are the lower-case hex SHA-256 of the state and the nonce.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheDigestsAreTheLowerCaseHexSha256OfTheStateAndTheNonce(): void
    {
        $state = ProtocolState::generate();

        self::assertSame(hash('sha256', $state->state()->reveal()), $state->stateDigest());
        self::assertSame(hash('sha256', $state->nonce()->reveal()), $state->nonceDigest());
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $state->stateDigest());
        self::assertMatchesRegularExpression('/^[0-9a-f]{64}$/D', $state->nonceDigest());
        self::assertNotSame($state->stateDigest(), $state->nonceDigest());
    }

    /**
     * The challenge is the verifier's S256 challenge, per RFC 7636 Appendix B.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheChallengeIsTheS256ChallengeOfThePkceVerifier(): void
    {
        $state    = ProtocolState::generate();
        $verifier = $state->codeVerifier()->reveal();
        $expected = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');

        self::assertSame($expected, $state->codeChallenge());
        self::assertMatchesRegularExpression(self::VALUE, $state->codeChallenge());
        self::assertStringNotContainsString('=', $state->codeChallenge());
    }

    /**
     * A dump and the JSON form show none of the values.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNoValueIsEverDumpedOrEncoded(): void
    {
        $state    = ProtocolState::generate();
        $redacted = ['state' => '[redacted]', 'nonce' => '[redacted]', 'code_verifier' => '[redacted]'];

        self::assertSame($redacted, $state->__debugInfo());
        self::assertSame($redacted, $state->jsonSerialize());
        self::assertSame('{"state":"[redacted]","nonce":"[redacted]","code_verifier":"[redacted]"}', json_encode($state));

        $dumped = (string) (new CliDumper)->dump((new VarCloner)->cloneVar($state), true);

        $printed  = print_r($state, true);
        $exported = var_export($state, true);

        foreach ([$state->state(), $state->nonce(), $state->codeVerifier()] as $secret) {
            self::assertStringNotContainsString($secret->reveal(), $dumped);
            self::assertStringNotContainsString($secret->reveal(), $printed);
            self::assertStringNotContainsString($secret->reveal(), $exported);
        }
    }

    /**
     * The state refuses to be serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheStateRefusesToBeSerialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A protocol state cannot be serialised.');

        serialize(ProtocolState::generate());
    }

    /**
     * The state refuses to be unserialised.
     *
     * @return void
     */
    public function testTheStateRefusesToBeUnserialized(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A protocol state cannot be unserialised.');

        unserialize('O:' . strlen(ProtocolState::class) . ':"' . ProtocolState::class . '":0:{}');
    }
}
