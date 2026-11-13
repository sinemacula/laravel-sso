<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Seams\Concerns;

use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;

/**
 * What every `Contracts\LinkEmailMatcher` must guarantee, as tests: use it in a
 * test case of the binding and implement the methods it declares.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
trait LinkEmailMatcherContract
{
    /**
     * Inside a transaction on the storage connection, a verified email matches
     * its identity alone; an unverified one, an unknown one, and addresses that
     * differ from the verified one by a subaddress or a dot match nobody.
     *
     * @return void
     */
    public function testLinkEmailMatcherMatchesOnlyAVerifiedEmail(): void
    {
        $verified = $this->identityWithEmail('kit.person@kit.example.com', true);

        $this->identityWithEmail('kit.unverified@kit.example.com', false);

        $matcher = $this->linkEmailMatcher();
        $tenant  = $this->linkEmailTenant();

        $emails  = ['kit.person@kit.example.com', 'kit.unverified@kit.example.com', 'kit.nobody@kit.example.com', 'kit.person+x@kit.example.com', 'kitperson@kit.example.com'];
        $matches = DB::connection(StorageConnection::name())->transaction(static fn (): array => array_map(
            static fn (string $email): LinkEmailMatch => $matcher->match(new LinkEmailQuery($tenant, $email, 'kit.example.com')),
            $emails,
        ));

        Assert::assertTrue($matches[0]->isSolely($verified), 'A verified email must match its identity alone.');

        foreach (array_slice($matches, 1, null, true) as $index => $match) {
            Assert::assertTrue($match->identity === null && !$match->ambiguous, sprintf('[%s] must match nobody.', $emails[$index]));
        }
    }

    /**
     * The binding under test.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher
     */
    abstract protected function linkEmailMatcher(): LinkEmailMatcher;

    /**
     * The tenant the emails are matched in.
     *
     * @return string
     */
    abstract protected function linkEmailTenant(): string;

    /**
     * An identity of the tenant holding the email, verified or not.
     *
     * @param  string  $email
     * @param  bool  $verified
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    abstract protected function identityWithEmail(string $email, bool $verified): IdentityReference;
}
