<?php

declare(strict_types = 1);

namespace Tests\Feature\Handoffs;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Handoffs\HandoffBinding;
use SineMacula\Laravel\Sso\Handoffs\RecheckLock;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\Enums\LinkOrigin;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\Fixtures\Clients;
use Tests\Fixtures\Results\ExampleResults;
use Tests\TestCase;

/**
 * Feature tests for what a purpose's branch of a redemption judges.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(RedemptionContext::class)]
final class RedemptionContextTest extends TestCase
{
    /**
     * A context names no caller and no link provenance unless given them.
     *
     * @return void
     */
    public function testNamesNoCallerOrProvenanceByDefault(): void
    {
        $result     = ExampleResults::full();
        $binding    = new HandoffBinding(trustVersion: 0);
        $connection = new Connection;
        $lock       = RecheckLock::held('tenant-1', 'connection-1', 'web', $connection, null);
        $client     = Clients::browser();
        $context    = new RedemptionContext($result, $binding, $lock, $connection, $client);

        self::assertSame([$result, $binding, $lock, $connection, $client], [$context->result, $context->binding, $context->lock, $context->connection, $context->client]);
        self::assertNull($context->caller);
        self::assertNull($context->linkProvenance);
    }

    /**
     * A context keeps the caller and the link provenance it is given.
     *
     * @return void
     */
    public function testKeepsTheCallerAndProvenance(): void
    {
        $connection = new Connection;
        $caller     = new Caller(new IdentityReference('user', '1'));
        $context    = new RedemptionContext(
            ExampleResults::full(),
            new HandoffBinding(trustVersion: 0),
            RecheckLock::held('tenant-1', 'connection-1', 'web', $connection, null),
            $connection,
            Clients::browser(),
            $caller,
            LinkOrigin::VERIFIED_DOMAIN,
        );

        self::assertSame($caller, $context->caller);
        self::assertSame(LinkOrigin::VERIFIED_DOMAIN, $context->linkProvenance);
    }
}
