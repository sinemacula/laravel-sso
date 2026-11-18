<?php

declare(strict_types = 1);

namespace Tests\Feature\Testing\Seams\Concerns;

use PHPUnit\Framework\AssertionFailedError;
use PHPUnit\Framework\Attributes\CoversTrait;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Linking\LinkEmailMatch;
use SineMacula\Laravel\Sso\Linking\LinkEmailQuery;
use SineMacula\Laravel\Sso\Testing\Seams\Concerns\LinkEmailMatcherContract;
use Tests\TestCase;

/**
 * Feature tests for the link email matcher kit, run against a binding that
 * keeps it and ones that do not.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(LinkEmailMatcherContract::class)]
final class LinkEmailMatcherContractTest extends TestCase
{
    use LinkEmailMatcherContract;

    /** @var list<array{0: string, 1: bool, 2: \SineMacula\Laravel\Sso\Identities\IdentityReference}> Each email held, whether verified, and its identity. */
    private array $emails = [];

    /** @var ?string How the binding breaks the contract, if it does. */
    private ?string $flaw = null;

    /**
     * Rows of `[flaw, email]`: matchers the kit fails, and the email each
     * matches that must match nobody.
     *
     * @return iterable<string, array{0: string, 1: string}>
     */
    public static function provideFlaws(): iterable
    {
        yield 'counting an unverified email' => ['unverified', 'kit.unverified@kit.example.com'];
        yield 'dropping a subaddress' => ['subaddress', 'kit.person+x@kit.example.com'];
        yield 'folding dots' => ['dots', 'kitperson@kit.example.com'];
        yield 'finding an unknown email ambiguous' => ['ambiguous', 'kit.nobody@kit.example.com'];
    }

    /**
     * The kit fails a matcher that loosens the match.
     *
     * @param  string  $flaw
     * @param  string  $email
     * @return void
     */
    #[DataProvider('provideFlaws')]
    public function testCatchesALooseMatcher(string $flaw, string $email): void
    {
        $this->flaw = $flaw;

        $this->expectException(AssertionFailedError::class);
        $this->expectExceptionMessage("[{$email}] must match nobody.");

        $this->testLinkEmailMatcherMatchesOnlyAVerifiedEmail();
    }

    /**
     * A matcher over the emails held, broken as the test says.
     *
     * @return \SineMacula\Laravel\Sso\Contracts\LinkEmailMatcher
     */
    #[\Override]
    protected function linkEmailMatcher(): LinkEmailMatcher
    {
        return new readonly class ($this->emails, $this->flaw) implements LinkEmailMatcher {
            /**
             * Constructor.
             *
             * @param  list<array{0: string, 1: bool, 2: \SineMacula\Laravel\Sso\Identities\IdentityReference}>  $emails
             * @param  ?string  $flaw
             */
            public function __construct(

                /** Each email held, whether verified, and its identity. */
                private array $emails,

                /** How the binding breaks the contract, if it does. */
                private ?string $flaw,
            ) {}

            /**
             * The one identity holding the email verified, or none.
             *
             * @param  \SineMacula\Laravel\Sso\Linking\LinkEmailQuery  $query
             * @return \SineMacula\Laravel\Sso\Linking\LinkEmailMatch
             */
            #[\Override]
            public function match(LinkEmailQuery $query): LinkEmailMatch
            {
                $email = $this->flaw === 'subaddress' ? (string) preg_replace('/\+[^@]*@/', '@', $query->email()) : $query->email();

                $fold = fn (string $address): string => $this->flaw === 'dots' ? (string) preg_replace('/\.(?=[^@]*@)/', '', $address) : $address;
                $held = array_filter($this->emails, fn (array $row): bool => $fold($row[0]) === $fold($email) && ($row[1] || $this->flaw === 'unverified'));

                if ($held === []) {
                    $unknown = !in_array($email, array_column($this->emails, 0), true);

                    return $unknown && $this->flaw === 'ambiguous' ? LinkEmailMatch::ambiguous() : LinkEmailMatch::none();
                }

                return LinkEmailMatch::exactlyOne(array_values($held)[0][2]);
            }
        };
    }

    /**
     * @return string
     */
    #[\Override]
    protected function linkEmailTenant(): string
    {
        return 'tenant-1';
    }

    /**
     * @param  string  $email
     * @param  bool  $verified
     * @return \SineMacula\Laravel\Sso\Identities\IdentityReference
     */
    #[\Override]
    protected function identityWithEmail(string $email, bool $verified): IdentityReference
    {
        $identity = new IdentityReference('App\Models\User', (string) (count($this->emails) + 1));

        $this->emails[] = [$email, $verified, $identity];

        return $identity;
    }
}
