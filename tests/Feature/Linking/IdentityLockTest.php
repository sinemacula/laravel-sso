<?php

declare(strict_types = 1);

namespace Tests\Feature\Linking;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\IdentityLock;
use SineMacula\Laravel\Sso\Linking\LinkingDiscovery;
use SineMacula\Laravel\Sso\Models\IdentityGuard;
use Tests\Concerns\RecordsLockOrder;

/**
 * Feature tests of the identity's guard.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(IdentityLock::class)]
#[CoversClass(IdentityGuard::class)]
#[CoversClass(LinkingDiscovery::class)]
final class IdentityLockTest extends LinkingTestCase
{
    use RecordsLockOrder;

    /**
     * With no transaction open it is a `LogicException`, since the lock would
     * end with its statement, and nothing is written.
     *
     * @return void
     */
    public function testItNeedsATransaction(): void
    {
        try {
            app(IdentityLock::class)->acquire($this->person);
            self::fail('The guard was taken with no transaction open.');
        } catch (\LogicException $exception) {
            self::assertSame('An identity is locked inside a transaction on the package\'s storage connection.', $exception->getMessage());
        }

        self::assertSame(0, IdentityGuard::query()->count());
    }

    /**
     * It is one statement, the row's first time and every time after, and the
     * row keeps its id and its time.
     *
     * @return void
     */
    public function testItIsOneStatementThatLeavesARowAsItWas(): void
    {
        $this->recordLockOrder();

        $this->acquire();

        self::assertSame(['identity guard'], $this->lockOrder());

        $first = IdentityGuard::query()->sole();

        $this->clock->advance(3600);
        $this->acquire();

        self::assertSame(['identity guard', 'identity guard'], $this->lockOrder());

        $again = IdentityGuard::query()->sole();

        self::assertSame($first->id, $again->id);
        self::assertSame($first->created_at->toIso8601String(), $again->created_at->toIso8601String());
        self::assertSame(IdentityLock::digest($this->person), $again->identity_hash);
    }

    /**
     * The domain link mark is stamped once on the guard's row and never moved
     * or cleared.
     *
     * @return void
     */
    public function testTheMarkOfADomainLinkHeld(): void
    {
        $other = new IdentityReference($this->person->type, '8');
        $held  = fn (IdentityReference $identity): bool => $this->connection->getConnection()->transaction(static fn (): bool => IdentityLock::hasHeldDomainLink($identity));
        $mark  = function (): void {
            $this->connection->getConnection()->transaction(function (): void {
                app(IdentityLock::class)->acquire($this->person);
                app(IdentityLock::class)->recordDomainLink($this->person);
            });
        };
        $markOf = static fn (IdentityReference $identity): ?string => IdentityGuard::query()
            ->where('identity_hash', IdentityLock::digest($identity))
            ->sole()
            ->domain_linked_at
            ?->toIso8601String();

        self::assertFalse($held($this->person), 'No row.');

        $this->acquire();
        $this->connection->getConnection()->transaction(static function () use ($other): void {
            app(IdentityLock::class)->acquire($other);
        });

        self::assertFalse($held($this->person), 'An unmarked row.');
        self::assertNull($markOf($this->person));

        $mark();

        self::assertSame('2026-11-01T09:30:00+00:00', $markOf($this->person));

        $this->clock->advance(3600);
        $mark();
        $this->acquire();

        self::assertSame('2026-11-01T09:30:00+00:00', $markOf($this->person));

        $this->recordLockOrder();

        self::assertTrue($held($this->person));
        self::assertSame(['identity mark'], $this->lockOrder());
        self::assertFalse($held($other));
        self::assertNull($markOf($other));
    }

    /**
     * The digest is lower-case SHA-256 and differs for any differing byte, the
     * type and id boundary included.
     *
     * @return void
     */
    public function testTheDigestTellsIdentitiesApart(): void
    {
        $digest = IdentityLock::digest($this->person);

        self::assertMatchesRegularExpression('/\A[0-9a-f]{64}\z/', $digest);
        self::assertSame($digest, IdentityLock::digest(new IdentityReference($this->person->type, $this->person->id)));
        self::assertNotSame($digest, IdentityLock::digest(new IdentityReference($this->person->type, '8')));
        self::assertNotSame($digest, IdentityLock::digest(new IdentityReference('App\Models\Admin', $this->person->id)));
        self::assertNotSame(IdentityLock::digest(new IdentityReference('ab', 'c')), IdentityLock::digest(new IdentityReference('a', 'bc')));
        self::assertNotSame(IdentityLock::digest(new IdentityReference('a', 'B')), IdentityLock::digest(new IdentityReference('a', 'b')));
    }

    /**
     * What plain reads hand a completion: whether it locks the claim, whether
     * the subject was held, and whose guard comes first.
     *
     * @return void
     */
    public function testWhatDiscoveryAnswers(): void
    {
        $none = LinkingDiscovery::notApplicable();
        $held = LinkingDiscovery::subjectHeld();
        $open = LinkingDiscovery::open($this->person);
        $bare = LinkingDiscovery::open(null);

        self::assertSame([false, false, null], [$none->locksDomain, $none->subjectHeld, $none->identity]);
        self::assertSame([false, true, null], [$held->locksDomain, $held->subjectHeld, $held->identity]);
        self::assertSame([true, false, $this->person], [$open->locksDomain, $open->subjectHeld, $open->identity]);
        self::assertSame([true, false, null], [$bare->locksDomain, $bare->subjectHeld, $bare->identity]);
    }

    /**
     * Take the person's guard, in a transaction.
     *
     * @return void
     */
    private function acquire(): void
    {
        $this->connection->getConnection()->transaction(fn () => app(IdentityLock::class)->acquire($this->person));
    }
}
