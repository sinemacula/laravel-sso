<?php

declare(strict_types = 1);

namespace Tests\Unit\Revocation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Enforcement\EnforcementPolicy;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationReason;
use SineMacula\Laravel\Sso\Revocation\Enums\RevocationScopeKind;
use SineMacula\Laravel\Sso\Revocation\RevocationScope;

/**
 * Unit tests for the scope of a session revocation (SSO-4.5, SSO-8.8): the four
 * scopes, each with its reason and only the fields it needs, the reasons a
 * connection's sessions may be revoked for, and the stable enum values.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RevocationScope::class)]
#[CoversClass(RevocationReason::class)]
#[CoversClass(RevocationScopeKind::class)]
final class RevocationScopeTest extends TestCase
{
    /**
     * The tenant scope carries the policy now in force, for its enforcing
     * tenant, and nothing else.
     *
     * @return void
     */
    public function testTheTenantScopeCarriesThePolicy(): void
    {
        $policy = EnforcementPolicy::required('child-1', 'parent-1', ['c-1'], 'v1');
        $scope  = RevocationScope::tenant($policy);

        self::assertSame(RevocationScopeKind::TENANT, $scope->kind);
        self::assertSame(RevocationReason::ENFORCEMENT_CHANGED, $scope->reason);
        self::assertSame('parent-1', $scope->tenantId);
        self::assertSame($policy, $scope->policy);
        self::assertNull($scope->connectionId);
        self::assertNull($scope->identity);
    }

    /**
     * The connection scope is for a disabled or deleted connection only.
     *
     * @return void
     */
    public function testTheConnectionScopeIsForADisabledOrDeletedConnection(): void
    {
        $disabled = RevocationScope::connection('tenant-1', 'c-1', RevocationReason::CONNECTION_DISABLED);
        $deleted  = RevocationScope::connection('tenant-1', 'c-1', RevocationReason::CONNECTION_DELETED);

        self::assertSame(RevocationScopeKind::CONNECTION, $disabled->kind);
        self::assertSame(RevocationReason::CONNECTION_DISABLED, $disabled->reason);
        self::assertSame(RevocationReason::CONNECTION_DELETED, $deleted->reason);
        self::assertSame('c-1', $deleted->connectionId);
        self::assertNull($deleted->policy);

        $this->expectException(\InvalidArgumentException::class);

        RevocationScope::connection('tenant-1', 'c-1', RevocationReason::LINK_REMOVED);
    }

    /**
     * The identity scope names the identity, the connection and the link that
     * was removed, so an adapter can revoke exactly that link's sessions.
     *
     * @return void
     */
    public function testTheIdentityScopeNamesTheIdentityTheConnectionAndTheLink(): void
    {
        $identity = new IdentityReference('App\Models\User', '7');
        $scope    = RevocationScope::identityInConnection('tenant-1', 'c-1', $identity, 'link-1');

        self::assertSame(RevocationScopeKind::IDENTITY_CONNECTION, $scope->kind);
        self::assertSame(RevocationReason::LINK_REMOVED, $scope->reason);
        self::assertSame('tenant-1', $scope->tenantId);
        self::assertSame($identity, $scope->identity);
        self::assertSame('c-1', $scope->connectionId);
        self::assertSame('link-1', $scope->linkId);
        self::assertNull($scope->policy);
    }

    /**
     * The link scope names the identity, the connection and the one link, for a
     * widened scope.
     *
     * @return void
     */
    public function testTheLinkScopeNamesTheIdentityAndTheLink(): void
    {
        $identity = new IdentityReference('App\Models\User', '7');
        $scope    = RevocationScope::identityLink('tenant-1', 'c-1', $identity, 'link-1');

        self::assertSame(RevocationScopeKind::IDENTITY_LINK, $scope->kind);
        self::assertSame(RevocationReason::SCOPE_WIDENED, $scope->reason);
        self::assertSame('tenant-1', $scope->tenantId);
        self::assertSame('c-1', $scope->connectionId);
        self::assertSame($identity, $scope->identity);
        self::assertSame('link-1', $scope->linkId);
        self::assertNull($scope->policy);
    }

    /**
     * Rows of `[build]`: each identity scope with an empty link id.
     *
     * @return iterable<string, array{\Closure(): \SineMacula\Laravel\Sso\Revocation\RevocationScope}>
     */
    public static function provideScopesMissingTheirLink(): iterable
    {
        $identity = new IdentityReference('App\Models\User', '7');

        yield 'a widened scope' => [static fn (): RevocationScope => RevocationScope::identityLink('tenant-1', 'c-1', $identity, '')];

        yield 'a removed link' => [static fn (): RevocationScope => RevocationScope::identityInConnection('tenant-1', 'c-1', $identity, '')];
    }

    /**
     * Each identity scope needs its link, by both constructors.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Revocation\RevocationScope  $build
     * @return void
     */
    #[DataProvider('provideScopesMissingTheirLink')]
    public function testALinkScopeNeedsItsLink(\Closure $build): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A revocation scope of a link names the link.');

        $build();
    }

    /**
     * Rows of `[build]`: each connection scope with an empty tenant, and with
     * an empty connection.
     *
     * @return iterable<string, array{\Closure(): \SineMacula\Laravel\Sso\Revocation\RevocationScope}>
     */
    public static function provideScopesMissingAnId(): iterable
    {
        $identity = new IdentityReference('App\Models\User', '7');

        yield 'connection, no tenant' => [static fn (): RevocationScope => RevocationScope::connection('', 'c-1', RevocationReason::CONNECTION_DISABLED)];

        yield 'connection, no connection' => [static fn (): RevocationScope => RevocationScope::connection('tenant-1', '', RevocationReason::CONNECTION_DELETED)];

        yield 'identity, no tenant' => [static fn (): RevocationScope => RevocationScope::identityInConnection('', 'c-1', $identity, 'link-1')];

        yield 'identity, no connection' => [static fn (): RevocationScope => RevocationScope::identityInConnection('tenant-1', '', $identity, 'link-1')];

        yield 'link, no tenant' => [static fn (): RevocationScope => RevocationScope::identityLink('', 'c-1', $identity, 'link-1')];

        yield 'link, no connection' => [static fn (): RevocationScope => RevocationScope::identityLink('tenant-1', '', $identity, 'link-1')];
    }

    /**
     * A connection scope names its tenant and connection: either one empty is
     * refused, by both constructors.
     *
     * @param  \Closure(): \SineMacula\Laravel\Sso\Revocation\RevocationScope  $build
     * @return void
     */
    #[DataProvider('provideScopesMissingAnId')]
    public function testAConnectionScopeNamesItsTenantAndConnection(\Closure $build): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('A revocation scope names its tenant and connection.');

        $build();
    }

    /**
     * The values are these, in this order.
     *
     * @return void
     */
    public function testTheValuesAreStable(): void
    {
        self::assertSame(['tenant', 'connection', 'identity_connection', 'identity_link'], array_column(RevocationScopeKind::cases(), 'value'));
        self::assertSame(['enforcement_changed', 'connection_disabled', 'connection_deleted', 'link_removed', 'scope_widened'], array_column(RevocationReason::cases(), 'value'));
    }
}
