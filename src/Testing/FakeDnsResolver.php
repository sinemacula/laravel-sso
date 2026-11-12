<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing;

use PHPUnit\Framework\Assert;
use SineMacula\Laravel\Sso\Contracts\DnsResolver;
use SineMacula\Laravel\Sso\Domains\DnsLookup;
use SineMacula\Laravel\Sso\Domains\DomainSummary;

/**
 * A test DNS resolver that answers each name as told and records every lookup;
 * an unexpected name throws, so a stray lookup fails the test.
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
     * Answer the claimed domain's record name with its token, as if published.
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
     * Answer every lookup of the name, replacing any earlier answer; a closure
     * can change the answer between lookups.
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
     * Record and answer the lookup.
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
     * Assert the name was looked up, exactly `$times` times if given.
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
