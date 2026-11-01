<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\DomainSummary;

/**
 * A DNS resolver for tests that answers each name with what the test gave it
 * and records every lookup, so a test of a domain's verification or recheck
 * makes no DNS query (SSO-3.2, SSO-12.4).
 *
 * Bind it in place of the package's resolver with
 * `$app->instance(DnsResolver::class, $dns = new FakeDnsResolver())`, give each
 * name its answer, then assert what was looked up:
 *
 * - `publishes($result->domain)` answers a claimed domain's record name with
 *   its token, as if the tenant had published the record;
 * - `found($name, ...$records)`, `absent($name)` and `failing($name)` answer a
 *   name with those records, with none, or with `lookup_failed`;
 * - `answer($name, $lookup)` answers with a `DnsLookup`, or with a closure that
 *   builds one from the name, for an answer that changes between lookups.
 *
 * Names are matched as DNS matches them, without regard to case or a trailing
 * dot; a later answer for a name replaces an earlier one. A lookup of a name
 * with no answer throws a `LogicException` naming it, so a stray lookup fails
 * the test rather than passing unnoticed. It holds its answers per instance and
 * never belongs in production.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class FakeDnsResolver implements DnsResolver
{
    /** @var array<string, \Closure(string): \SineMacula\Laravel\Sso\Domains\DnsLookup|\SineMacula\Laravel\Sso\Domains\DnsLookup> The answer to each name. */
    private array $answers = [];

    /** @var list<string> Every name looked up, in order, as asked. */
    private array $lookups = [];

    /**
     * Answer the claimed domain's record name with its token.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainSummary  $domain
     * @return self
     */
    public function publishes(DomainSummary $domain): self
    {
        return $this->found($domain->recordName, $domain->verificationToken());
    }

    /**
     * Answer the name with these TXT records, at least one.
     *
     * @param  string  $name
     * @param  string  ...$records
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function found(string $name, string ...$records): self
    {
        return $this->answer($name, DnsLookup::found(array_values($records)));
    }

    /**
     * Answer the name with no TXT record.
     *
     * @param  string  $name
     * @return self
     */
    public function absent(string $name): self
    {
        return $this->answer($name, DnsLookup::absent());
    }

    /**
     * Answer the name with a failed lookup.
     *
     * @param  string  $name
     * @return self
     */
    public function failing(string $name): self
    {
        return $this->answer($name, DnsLookup::lookupFailed());
    }

    /**
     * Answer every lookup of the name with the lookup, or with what the closure
     * builds from the name.
     *
     * @param  string  $name
     * @param  \Closure(string): \SineMacula\Laravel\Sso\Domains\DnsLookup|\SineMacula\Laravel\Sso\Domains\DnsLookup  $answer
     * @return self
     */
    public function answer(string $name, \Closure|DnsLookup $answer): self
    {
        $this->answers[self::key($name)] = $answer;

        return $this;
    }

    /**
     * Record the lookup and answer it with what was given for its name.
     *
     * @param  string  $name
     * @return \SineMacula\Laravel\Sso\Domains\DnsLookup
     *
     * @throws \LogicException
     */
    #[\Override]
    public function txt(string $name): DnsLookup
    {
        $this->lookups[] = $name;

        $answer = $this->answers[self::key($name)] ?? null;

        if ($answer === null) {
            throw new \LogicException(sprintf('The fake DNS resolver has no answer for [%s].', $name));
        }

        return $answer instanceof DnsLookup ? $answer : $answer($name);
    }

    /**
     * Every name looked up, in order.
     *
     * @return list<string>
     */
    public function lookups(): array
    {
        return $this->lookups;
    }

    /**
     * Assert the name was looked up, exactly as many times as given when a
     * number is.
     *
     * @param  string  $name
     * @param  ?int  $times
     * @return void
     */
    public function assertLookedUp(string $name, ?int $times = null): void
    {
        $count = count(array_filter($this->lookups, static fn (string $looked): bool => self::key($looked) === self::key($name)));

        if ($times === null) {
            Assert::assertGreaterThan(0, $count, sprintf('Expected [%s] to be looked up; it was not.', $name));

            return;
        }

        Assert::assertSame($times, $count, sprintf('Expected [%s] to be looked up %d times; it was looked up %d.', $name, $times, $count));
    }

    /**
     * Assert nothing was looked up.
     *
     * @return void
     */
    public function assertNothingLookedUp(): void
    {
        Assert::assertSame([], $this->lookups, 'Expected nothing to be looked up.');
    }

    /**
     * The name as DNS compares it: lower case, with no trailing dot.
     *
     * @param  string  $name
     * @return string
     */
    private static function key(string $name): string
    {
        return rtrim(strtolower($name), '.');
    }
}
