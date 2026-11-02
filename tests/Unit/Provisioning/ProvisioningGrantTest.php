<?php

declare(strict_types = 1);

namespace Tests\Unit\Provisioning;

use Carbon\CarbonImmutable;
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
 * claim answers nothing and spends it all the same; closing voids it; and it
 * can be neither copied nor read.
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
