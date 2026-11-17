<?php

declare(strict_types = 1);

namespace Tests\Unit\Protocols\Oidc\Jose;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\AlgorithmAllowList;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\Enums\KeySelectionOutcome;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\KeySelection;
use SineMacula\Laravel\Sso\Protocols\Oidc\Jose\ProviderKey;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Testing\Oidc\FakeSigningKey;

/**
 * Unit tests for the outcome of choosing an ID token's key.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(KeySelection::class)]
final class KeySelectionTest extends TestCase
{
    /**
     * An overtaken selection carries no key and is neither found nor unknown.
     *
     * @return void
     */
    public function testAnOvertakenSelectionHasNoKey(): void
    {
        $selection = KeySelection::overtaken();

        self::assertSame(KeySelectionOutcome::OVERTAKEN, $selection->outcome);
        self::assertNull($selection->key);
        self::assertSame([true, false, false], [$selection->isOvertaken(), $selection->isFound(), $selection->isUnknown()]);
        self::assertFalse(KeySelection::unknown()->isOvertaken());
    }

    /**
     * A receipt is attached without changing the outcome or the key.
     *
     * @return void
     *
     * @throws \LogicException
     */
    public function testAReceiptKeepsTheOutcomeAndKey(): void
    {
        $key      = ProviderKey::admit(FakeSigningKey::rsa()->jwk(), AlgorithmAllowList::of(['RS256'])) ?? throw new \LogicException('The key was refused.');
        $receipt  = new TransitionReceipt('c', 'request-1', 4, 5, 7);
        $found    = KeySelection::found($key);
        $attached = $found->withReceipt($receipt);

        self::assertNull($found->receipt);
        self::assertSame($receipt, $attached->receipt);
        self::assertSame($key, $attached->key);
        self::assertTrue($attached->isFound());
    }
}
