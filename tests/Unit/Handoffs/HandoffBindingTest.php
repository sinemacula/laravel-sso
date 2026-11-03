<?php

declare(strict_types = 1);

namespace Tests\Unit\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

/**
 * Pins the frozen shape of what a handoff code was bound to, which a redeemer
 * builds from its own store and hands to `Handoffs\HandoffRecheck`: exactly
 * these six parts, in this order, each optional and `null` by default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(HandoffBinding::class)]
final class HandoffBindingTest extends TestCase
{
    /**
     * Every part is kept, under its own name and in its own place.
     *
     * @return void
     */
    public function testKeepsEveryPartInItsPlace(): void
    {
        $linked   = new IdentityReference('user', '1');
        $identity = new IdentityReference('user', '2');
        $binding  = new HandoffBinding($linked, 'link-1', $identity, 'session-1', 'reservation-1', 'handoff-1', 3);

        self::assertSame([
            'linkedIdentity'   => $linked,
            'linkId'           => 'link-1',
            'identity'         => $identity,
            'sessionId'        => 'session-1',
            'reservationId'    => 'reservation-1',
            'handoffReference' => 'handoff-1',
            'trustVersion'     => 3,
        ], get_object_vars($binding));
    }

    /**
     * A binding of nothing is an unlinked `sign_in`'s: every part is `null`,
     * its trust version included, which the recheck refuses.
     *
     * @return void
     */
    public function testEveryPartDefaultsToNull(): void
    {
        self::assertSame([
            'linkedIdentity'   => null,
            'linkId'           => null,
            'identity'         => null,
            'sessionId'        => null,
            'reservationId'    => null,
            'handoffReference' => null,
            'trustVersion'     => null,
        ], get_object_vars(new HandoffBinding));
    }

    /**
     * Each part may be given by name alone, leaving the others `null`, as an
     * adapter binding a `link` does.
     *
     * @return void
     */
    public function testAPartGivenByNameLeavesTheOthersNull(): void
    {
        $identity = new IdentityReference('user', '2');

        self::assertSame([
            'linkedIdentity'   => null,
            'linkId'           => 'link-1',
            'identity'         => $identity,
            'sessionId'        => null,
            'reservationId'    => null,
            'handoffReference' => null,
            'trustVersion'     => null,
        ], get_object_vars(new HandoffBinding(linkId: 'link-1', identity: $identity)));
    }

    /**
     * A binding never changes once it is made.
     *
     * @return void
     */
    public function testIsImmutable(): void
    {
        $binding = new HandoffBinding(linkId: 'link-1');

        $this->expectException(\Error::class);
        $this->expectExceptionMessage('Cannot modify readonly property ' . HandoffBinding::class . '::$linkId');

        // @phpstan-ignore property.readOnlyAssignOutOfClass
        $binding->linkId = 'link-2';
    }
}
