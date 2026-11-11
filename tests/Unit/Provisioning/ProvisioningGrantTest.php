<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Carbon\CarbonImmutable;
use Illuminate\Database\DatabaseTransactionRecord;
use Illuminate\Database\DatabaseTransactionsManager;
use Illuminate\Foundation\Testing\DatabaseTransactionsManager as TestingTransactionsManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Protocols\TransitionReceipt;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\AuthenticationContext;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Concerns\DumpsValues;

/**
 * Unit tests pinning the provisioning grant's lifecycle (SSO-8.6): it starts
 * usable; the one claim of the exact result answers the request's id; any other
 * claim answers nothing and spends it for good; only the rollback of the
 * outermost transaction a claim is bound to releases it, once its manager no
 * longer holds it; closing voids it; and it can be neither copied nor read.
 * Transactions are driven through Laravel's managers directly, as a connection
 * drives them.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ProvisioningGrant::class)]
final class ProvisioningGrantTest extends TestCase
{
    use DumpsValues;

    /** @var string The request's id. */
    private const string REQUEST_ID = '01jbexamplerequest00000001';

    /** @var string The subject the result carries. */
    private const string SUBJECT = 'the-subject-of-the-result';

    /** @var string The attribute the result carries. */
    private const string ATTRIBUTE = 'attribute-of-the-result';

    /** @var string The issuer the result carries. */
    private const string ISSUER = 'https://idp.example.com/of-the-result';

    /** @var string The connection the transactions run on. */
    private const string CONNECTION = 'storage';

    /**
     * Its constructor is private: only `issue()` makes one.
     *
     * @return void
     */
    public function testItCannotBeConstructed(): void
    {
        $constructor = (new \ReflectionClass(ProvisioningGrant::class))->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());
    }

    /**
     * A grant starts usable, with its deadline and no receipt.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testItStartsUsable(): void
    {
        $until = CarbonImmutable::parse('2026-11-01T09:32:00Z');
        $grant = ProvisioningGrant::issue(self::verifiedResult(), self::REQUEST_ID, $until);

        self::assertTrue($grant->isUsable());
        self::assertSame($until, $grant->verifiedUntil());
        self::assertNull($grant->transitionReceipt());
    }

    /**
     * It carries the receipt it was issued with, exactly.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testItCarriesItsReceipt(): void
    {
        $receipt = new TransitionReceipt('c1', self::REQUEST_ID, 4, 5, 7);

        self::assertSame($receipt, ProvisioningGrant::issue(self::verifiedResult(), self::REQUEST_ID, self::until(), $receipt)->transitionReceipt());
    }

    /**
     * The first claim of the exact result answers the request's id, and spends
     * the grant; every later claim answers nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheFirstClaimOfTheExactResultIsTheOnlyOne(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        self::assertSame(self::REQUEST_ID, $grant->claim($result));
        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));
        self::assertFalse($grant->isUsable());
    }

    /**
     * A claim of another object with the same fields answers nothing, and
     * spends the grant: the exact result gets nothing after it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClaimOfACopySpendsTheGrant(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        self::assertEquals($result, clone $result);
        self::assertNull($grant->claim(clone $result));
        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));
    }

    /**
     * Whether it is bound to a result claims nothing, and is exact: a copy with
     * the same fields is another result.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testBeingBoundToAResultClaimsNothing(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        self::assertTrue($grant->isBoundTo($result));
        self::assertFalse($grant->isBoundTo(clone $result));
        self::assertTrue($grant->isUsable());
    }

    /**
     * A claim bound to a transaction that rolls back is released once the
     * manager has let it go, and the exact result claims the grant again.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARolledBackClaimCanBeClaimedAgain(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);

        self::assertSame(self::REQUEST_ID, $grant->claim($result));

        $grant->bind($manager, self::CONNECTION);

        self::assertFalse($grant->isUsable());
        self::assertFalse(self::isUsableDuringRollback($grant, $manager, 0), 'not before its manager lets it go');
        self::assertTrue($grant->isUsable());
        self::assertSame(['usable' => true], $grant->jsonSerialize());
        self::assertSame(self::REQUEST_ID, $grant->claim($result));
        self::assertFalse($grant->isUsable());
    }

    /**
     * A claim bound to a transaction that commits stays used, even from a
     * commit callback of that same commit, which runs once the manager has let
     * the transaction go.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACommittedClaimCannotBeClaimedAgain(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;
        $claimed = 'not run';

        $manager->begin(self::CONNECTION, 1);
        $manager->addCallback(static function () use ($grant, $result, &$claimed): void {
            $claimed = $grant->claim($result);
        });

        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $manager->commit(self::CONNECTION, 1, 0);

        self::assertNull($claimed);
        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));
    }

    /**
     * A claim made again after a rollback is bound afresh, to its own
     * transaction: its rollback releases it again, and its commit leaves it
     * used.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClaimMadeAgainIsJudgedByItsOwnTransaction(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        foreach (['rolls back' => true, 'rolls back again' => true, 'commits' => false] as $how => $rollsBack) {

            $manager->begin(self::CONNECTION, 1);

            self::assertSame(self::REQUEST_ID, $grant->claim($result), $how);
            self::assertFalse($grant->isUsable(), "unbound, before it {$how}");

            $grant->bind($manager, self::CONNECTION);

            $rollsBack ? $manager->rollback(self::CONNECTION, 0) : $manager->commit(self::CONNECTION, 1, 0);

            self::assertSame($rollsBack, $grant->isUsable(), $how);
        }

        self::assertNull($grant->claim($result));
    }

    /**
     * The rollback callback of a transaction an earlier claim was bound to
     * marks nothing of a later claim.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAnEarlierTransactionsRollbackReleasesNoLaterClaim(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);

        $earlier = self::current($manager);

        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $manager->rollback(self::CONNECTION, 0);

        $manager->begin(self::CONNECTION, 1);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);

        $earlier->executeCallbacksForRollback();
        $manager->commit(self::CONNECTION, 1, 0);

        self::assertFalse($grant->isUsable());
    }

    /**
     * A refusal spends the grant for good: neither a refused claim nor an
     * attempt the helper refused is released by its transaction's rollback.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARefusedGrantIsNotReleasedByARollback(): void
    {
        $result   = self::verifiedResult();
        $refusals = [
            'a claim refused'    => static fn (ProvisioningGrant $grant): ?string => $grant->claim($result),
            'an attempt refused' => static function (ProvisioningGrant $grant): void {
                $grant->refuse();
            },
        ];

        foreach ($refusals as $how => $refuse) {

            $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
            $manager = new DatabaseTransactionsManager;

            $manager->begin(self::CONNECTION, 1);
            $grant->claim($result);
            $grant->bind($manager, self::CONNECTION);
            $refuse($grant);
            $manager->rollback(self::CONNECTION, 0);

            self::assertFalse($grant->isUsable(), $how);
            self::assertNull($grant->claim($result), $how);
        }
    }

    /**
     * A refused claim of a copy spends a grant nothing claimed: no rollback
     * releases it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClaimOfACopyIsNeverReleased(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);

        self::assertNull($grant->claim(clone $result));

        $grant->bind($manager, self::CONNECTION);
        $manager->rollback(self::CONNECTION, 0);

        self::assertFalse($grant->isUsable());
    }

    /**
     * A claim is bound to the outermost transaction, not the savepoint it was
     * made in: rolling the savepoint back leaves it used, and the outermost
     * transaction's rollback releases it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testARolledBackSavepointLeavesTheClaimUsed(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);
        $manager->begin(self::CONNECTION, 2);
        $manager->begin(self::CONNECTION, 3);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $manager->rollback(self::CONNECTION, 1);

        self::assertFalse($grant->isUsable());

        $manager->rollback(self::CONNECTION, 0);

        self::assertTrue($grant->isUsable());
    }

    /**
     * A claim made with no transaction open is bound to the first one begun:
     * until then it is used, and a second claim is refused; once bound, that
     * transaction's rollback releases it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClaimWithNoTransactionIsBoundToTheNextOne(): void
    {
        $result  = self::verifiedResult();
        $manager = new DatabaseTransactionsManager;

        foreach ([false, true] as $claimedAgain) {

            $grant = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

            $manager->begin('another', 1);
            $grant->claim($result);
            $grant->bind($manager, self::CONNECTION);
            $manager->rollback('another', 0);

            self::assertFalse($grant->isUsable(), 'unbound');

            if ($claimedAgain) {
                self::assertNull($grant->claim($result));
            }

            $manager->begin(self::CONNECTION, 1);
            $grant->bind($manager, self::CONNECTION);
            $manager->rollback(self::CONNECTION, 0);

            self::assertSame(!$claimedAgain, $grant->isUsable());
        }
    }

    /**
     * A claim stays bound to the first transaction it was bound to: binding it
     * again changes nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClaimIsBoundOnce(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);
        $manager->begin('another', 1);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $grant->bind($manager, 'another');
        $manager->rollback('another', 0);

        self::assertFalse($grant->isUsable());

        $manager->rollback(self::CONNECTION, 0);

        self::assertTrue($grant->isUsable());
    }

    /**
     * Under the testing traits' manager, the transaction wrapping the test is
     * not one a claim is bound to: with only it open, the claim is bound to the
     * next transaction, and otherwise to the outermost inside it.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testTheTestingWrapperIsNoTransactionOfTheClaim(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new TestingTransactionsManager([self::CONNECTION]);

        $manager->begin(self::CONNECTION, 1);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);

        $manager->begin(self::CONNECTION, 2);
        $manager->begin(self::CONNECTION, 3);
        $grant->bind($manager, self::CONNECTION);
        $manager->rollback(self::CONNECTION, 2);

        self::assertFalse($grant->isUsable(), 'a savepoint inside it');

        $manager->rollback(self::CONNECTION, 1);

        self::assertTrue($grant->isUsable());
    }

    /**
     * A claim bound under the testing traits' manager is used once its
     * transaction commits inside the wrapper.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testACommitInsideTheTestingWrapperLeavesTheClaimUsed(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new TestingTransactionsManager([self::CONNECTION]);

        $manager->begin(self::CONNECTION, 1);
        $manager->begin(self::CONNECTION, 2);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $manager->commit(self::CONNECTION, 2, 1);
        $manager->rollback(self::CONNECTION, 0);

        self::assertFalse($grant->isUsable());
    }

    /**
     * A closed grant stays void, whatever its claim's transaction came to.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testAClosedGrantIsNotReleased(): void
    {
        $result  = self::verifiedResult();
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());
        $manager = new DatabaseTransactionsManager;

        $manager->begin(self::CONNECTION, 1);
        $grant->claim($result);
        $grant->bind($manager, self::CONNECTION);
        $grant->close();
        $manager->rollback(self::CONNECTION, 0);

        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));
    }

    /**
     * Closing voids it: the exact result gets nothing, used or not, and closing
     * again changes nothing.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testClosingVoidsIt(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        $grant->close();

        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));

        $grant->close();

        self::assertFalse($grant->isUsable());
        self::assertNull($grant->claim($result));
    }

    /**
     * Closing a used grant leaves it unusable.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testClosingAUsedGrantLeavesItUnusable(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        $grant->claim($result);
        $grant->close();

        self::assertFalse($grant->isUsable());
    }

    /**
     * A dump and `json_encode()` show whether it is usable, as it changes.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testADumpAndJsonShowOnlyWhetherItIsUsable(): void
    {
        $result = self::verifiedResult();
        $grant  = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until());

        self::assertSame(['usable' => true], $grant->__debugInfo());
        self::assertSame(['usable' => true], $grant->jsonSerialize());
        self::assertSame('{"usable":true}', json_encode($grant));

        $grant->claim($result);

        self::assertSame(['usable' => false], $grant->__debugInfo());
        self::assertSame(['usable' => false], $grant->jsonSerialize());
        self::assertSame('{"usable":false}', json_encode($grant));
    }

    /**
     * No dump, export or array cast shows the result, the request's id or the
     * receipt, whether or not it is used.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testNothingShowsWhatItHolds(): void
    {
        $result  = self::verifiedResult();
        $receipt = new TransitionReceipt('receipt-connection', 'receipt-request', 4, 5, 7);
        $grant   = ProvisioningGrant::issue($result, self::REQUEST_ID, self::until(), $receipt);

        foreach ([false, true] as $used) {

            if ($used) {
                $grant->claim($result);
            }

            foreach ([...self::dumps($grant), 'array cast' => print_r((array) $grant, true), 'array cast export' => var_export((array) $grant, true)] as $how => $dump) {
                foreach ([self::SUBJECT, self::ATTRIBUTE, self::ISSUER, self::REQUEST_ID, 'receipt-connection', 'receipt-request'] as $secret) {
                    self::assertStringNotContainsString($secret, $dump, $how);
                }
            }
        }
    }

    /**
     * It refuses to be cloned, and a refused clone leaves it as it was.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testItCannotBeCloned(): void
    {
        $grant = ProvisioningGrant::issue(self::verifiedResult(), self::REQUEST_ID, self::until());

        self::assertSame('A provisioning grant cannot be cloned.', self::cloneRefusal($grant));
        self::assertTrue($grant->isUsable());
    }

    /**
     * It refuses to be serialised.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    public function testItCannotBeSerialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A provisioning grant cannot be serialised.');

        serialize(ProvisioningGrant::issue(self::verifiedResult(), self::REQUEST_ID, self::until()));
    }

    /**
     * It refuses to be unserialised.
     *
     * @return void
     */
    public function testItCannotBeUnserialised(): void
    {
        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('A provisioning grant cannot be unserialised.');

        unserialize('O:' . strlen(ProvisioningGrant::class) . ':"' . ProvisioningGrant::class . '":0:{}');
    }

    /**
     * Roll the manager's transactions on the connection back to the level, and
     * answer whether the grant was usable while the rollback ran its callbacks,
     * `null` if they never ran.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @param  int  $level
     * @return ?bool
     */
    private static function isUsableDuringRollback(ProvisioningGrant $grant, DatabaseTransactionsManager $manager, int $level): ?bool
    {
        $usable = null;

        self::current($manager)->addCallbackForRollback(static function () use ($grant, &$usable): void {
            $usable = $grant->isUsable();
        });

        $manager->rollback(self::CONNECTION, $level);

        return $usable;
    }

    /**
     * The innermost transaction the manager holds open on the connection.
     *
     * @param  \Illuminate\Database\DatabaseTransactionsManager  $manager
     * @return \Illuminate\Database\DatabaseTransactionRecord
     */
    private static function current(DatabaseTransactionsManager $manager): DatabaseTransactionRecord
    {
        $current = $manager->getPendingTransactions()->last(static fn (DatabaseTransactionRecord $record): bool => $record->connection === self::CONNECTION);

        self::assertInstanceOf(DatabaseTransactionRecord::class, $current);

        return $current;
    }

    /**
     * What cloning the grant is refused with, or what it made.
     *
     * @param  \SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant  $grant
     * @return string
     */
    private static function cloneRefusal(ProvisioningGrant $grant): string
    {
        try {
            return get_debug_type(clone $grant);
        } catch (\LogicException $exception) { // @phpstan-ignore catch.neverThrown (a clone runs `__clone()`, which reports no exception)
            return $exception->getMessage();
        }
    }

    /**
     * A result, with something to find in a dump.
     *
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \Random\RandomException
     */
    private static function verifiedResult(): VerifiedResult
    {
        return new VerifiedResult(
            self::ISSUER,
            self::SUBJECT,
            null,
            'connection-1',
            'tenant-1',
            'oidc',
            'web',
            Purpose::SIGN_IN,
            RequestReference::generate(),
            ['name' => self::ATTRIBUTE],
            false,
            new AuthenticationContext,
        );
    }

    /**
     * A deadline.
     *
     * @return \Carbon\CarbonImmutable
     */
    private static function until(): CarbonImmutable
    {
        return CarbonImmutable::parse('2026-11-01T09:32:00Z');
    }
}
