<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;
use SineMacula\Laravel\Sso\Models\Connection;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\LinkConfirmationContract;
use Tests\TestCase;

/**
 * Feature tests for the link confirmation kit, run against a binding that keeps
 * it and one that does not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(LinkConfirmationContract::class)]
final class LinkConfirmationContractTest extends TestCase
{
    use LinkConfirmationContract;

    /** @var array<string, string> Each independent session's identity id. */
    public const array SESSIONS = ['session-of-1' => '1', 'session-of-2' => '2'];

    /** @var string A session of identity 1 established through one of its domain links. */
    public const string THROUGH_A_DOMAIN_LINK = 'domain-session-of-1';

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /**
     * The kit fails a binding that finds any independent session enough.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatIgnoresTheSessionsIdentity(): void
    {
        $this->flaw = 'identity';

        $this->expectException(AssertionFailedError::class);

        $this->testLinkConfirmationFindsOnlyTheIdentitysOwnSessionIndependent();
    }

    /**
     * The kit fails a binding that finds every session of the identity's own
     * independent.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testCatchesABindingThatTrustsEveryOwnSession(): void
    {
        $this->flaw = 'owned';

        $this->expectException(AssertionFailedError::class);

        $this->testLinkConfirmationFindsOnlyTheIdentitysOwnSessionIndependent();
    }

    /**
     * A binding over two independent sessions, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\LinkConfirmation
     */
    #[\Override]
    protected function linkConfirmation(): LinkConfirmation
    {
        return new readonly class ($this->flaw) implements LinkConfirmation {
            /**
             * Constructor.
             *
             * @param  ?string  $flaw
             */
            public function __construct(

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,
            ) {}

            /**
             * Independent for the caller's own session.
             *
             * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
             * @param  \SineMacula\Laravel\Sso\Contracts\SsoConnection  $connection
             * @param  list<string>  $domainLinkIds
             * @return \SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict
             */
            #[\Override]
            public function judge(Caller $caller, SsoConnection $connection, array $domainLinkIds): LinkConfirmationVerdict
            {
                unset($connection, $domainLinkIds);

                $trusted = LinkConfirmationContractTest::SESSIONS;

                if ($this->flaw === 'owned') {
                    $trusted[LinkConfirmationContractTest::THROUGH_A_DOMAIN_LINK] = '1';
                }

                $owner       = $trusted[$caller->sessionId ?? ''] ?? null;
                $independent = $owner !== null && ($this->flaw === 'identity' || $owner === $caller->identity->id);

                return $independent ? LinkConfirmationVerdict::INDEPENDENT : LinkConfirmationVerdict::DEPENDENT;
            }
        };
    }

    /**
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    #[\Override]
    protected function confirmationConnection(): SsoConnection
    {
        return (new Connection)->forceFill(['id' => '01jbkitconnectionkitconne0', 'tenant_id' => 'tenant-1', 'protocol' => 'oidc']);
    }

    /**
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    #[\Override]
    protected function independentCaller(): Caller
    {
        return new Caller(new IdentityReference('App\Models\User', '1'), 'session-of-1');
    }

    /**
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    #[\Override]
    protected function dependentCaller(): Caller
    {
        return new Caller(new IdentityReference('App\Models\User', '1'), self::THROUGH_A_DOMAIN_LINK);
    }

    /**
     * @return string
     */
    #[\Override]
    protected function otherIdentitysSessionId(): string
    {
        return 'session-of-2';
    }

    /**
     * @return list<string>
     */
    #[\Override]
    protected function domainLinkIds(): array
    {
        return ['link-1'];
    }
}
