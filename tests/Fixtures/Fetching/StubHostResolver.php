<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Fetching;

use SineMacula\Laravel\Sso\Contracts\HostResolver;

/**
 * A host resolver for the package's own tests that answers each host with the
 * addresses a test gave it, and `[]` for any other, and records every host it
 * was asked, so no test resolves a name over the network.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class StubHostResolver implements HostResolver
{
    /** @var list<string> Every host asked, in order. */
    private array $lookups = [];

    /**
     * Constructor.
     *
     * @param  array<string, list<string>>  $addresses
     */
    public function __construct(

        /** The addresses of each host. */
        private readonly array $addresses = [],
    ) {}

    /**
     * The addresses given for the host, `[]` for a host given none.
     *
     * @param  string  $asciiHost
     * @return list<string>
     */
    #[\Override]
    public function addresses(string $asciiHost): array
    {
        $this->lookups[] = $asciiHost;

        return $this->addresses[$asciiHost] ?? [];
    }

    /**
     * Every host asked, in order.
     *
     * @return list<string>
     */
    public function lookups(): array
    {
        return $this->lookups;
    }
}
