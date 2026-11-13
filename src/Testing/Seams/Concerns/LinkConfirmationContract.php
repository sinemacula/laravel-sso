<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\LinkConfirmation;
use SineMacula\Laravel\Sso\Contracts\SsoConnection;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Linking\Enums\LinkConfirmationVerdict;

/**
 * What every `Contracts\LinkConfirmation` must guarantee, as tests: use it in a
 * test case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait LinkConfirmationContract
{
    /**
     * Inside a transaction on the storage connection, the independent caller is
     * `independent`; the same identity on a session through a domain link, on
     * another identity's session, or with no session is `dependent`.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testLinkConfirmationFindsOnlyTheIdentitysOwnSessionIndependent(): void
    {
        $confirmation = $this->linkConfirmation();
        $connection   = $this->confirmationConnection();
        $caller       = $this->independentCaller();
        $links        = $this->domainLinkIds();
        $others       = $this->otherIdentitysSessionId();
        $dependent    = $this->dependentCaller();

        $verdicts = DB::connection(StorageConnection::name())->transaction(static fn (): array => [
            $confirmation->judge($caller, $connection, $links),
            $confirmation->judge(new Caller($caller->identity, $others), $connection, $links),
            $confirmation->judge(new Caller($caller->identity), $connection, $links),
            $confirmation->judge($dependent, $connection, $links),
        ]);

        Assert::assertSame(LinkConfirmationVerdict::INDEPENDENT, $verdicts[0], 'The identity\'s own independent session must be independent.');
        Assert::assertSame(LinkConfirmationVerdict::DEPENDENT, $verdicts[1], 'Another identity\'s session must be dependent.');
        Assert::assertSame(LinkConfirmationVerdict::DEPENDENT, $verdicts[2], 'A caller with no session must be dependent.');
        Assert::assertSame(LinkConfirmationVerdict::DEPENDENT, $verdicts[3], 'The identity\'s own session through a domain link must be dependent.');
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\LinkConfirmation
     */
    abstract protected function linkConfirmation(): LinkConfirmation;

    /**
     * The connection the `link` is redeemed for.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\SsoConnection
     */
    abstract protected function confirmationConnection(): SsoConnection;

    /**
     * A caller on a session of its own identity that the binding finds
     * independent of the identity's domain links.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    abstract protected function independentCaller(): Caller;

    /**
     * The same identity on another session of its own, established through one
     * of its domain links.
     *
     * @return \SineMacula\Laravel\Sso\Identities\Caller
     */
    abstract protected function dependentCaller(): Caller;

    /**
     * The id of a session of another identity, independent for that identity.
     *
     * @return string
     */
    abstract protected function otherIdentitysSessionId(): string;

    /**
     * The domain links the caller's identity holds.
     *
     * @return list<string>
     */
    abstract protected function domainLinkIds(): array;
}
