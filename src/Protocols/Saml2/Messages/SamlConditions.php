<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * A verified assertion's `Conditions`, naming any unmodelled condition so
 * validation can refuse it (SAML 2.0 Core 2.5.1).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlConditions implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  ?\Carbon\CarbonImmutable  $notBefore
     * @param  ?\Carbon\CarbonImmutable  $notOnOrAfter
     * @param  list<list<string>>  $audienceRestrictions
     * @param  int  $oneTimeUse
     * @param  int  $proxyRestrictions
     * @param  list<string>  $otherConditions
     */
    public function __construct(
        // The `NotBefore` attribute
        ?CarbonImmutable $notBefore = null,
        // The `NotOnOrAfter` attribute
        ?CarbonImmutable $notOnOrAfter = null,
        // The audiences of each `AudienceRestriction`, in order
        array $audienceRestrictions = [],
        // How many `OneTimeUse` conditions it carries
        int $oneTimeUse = 0,
        // How many `ProxyRestriction` conditions it carries
        int $proxyRestrictions = 0,
        // The qualified name of every other condition, in order
        array $otherConditions = [],
    ) {
        $this->hold([
            'not_before'            => $notBefore,
            'not_on_or_after'       => $notOnOrAfter,
            'audience_restrictions' => $audienceRestrictions,
            'one_time_use'          => $oneTimeUse,
            'proxy_restrictions'    => $proxyRestrictions,
            'other_conditions'      => $otherConditions,
        ]);
    }

    /**
     * The `NotBefore` attribute, or `null` when absent.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function notBefore(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->held('not_before');
    }

    /**
     * The `NotOnOrAfter` attribute, or `null` when absent.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function notOnOrAfter(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->held('not_on_or_after');
    }

    /**
     * The audiences of each `AudienceRestriction`, each of which must hold.
     *
     * @return list<list<string>>
     */
    public function audienceRestrictions(): array
    {
        /** @var list<list<string>> */
        return $this->held('audience_restrictions');
    }

    /**
     * How many `OneTimeUse` conditions it carries.
     *
     * @return int
     */
    public function oneTimeUse(): int
    {
        /** @var int */
        return $this->held('one_time_use');
    }

    /**
     * How many `ProxyRestriction` conditions it carries.
     *
     * @return int
     */
    public function proxyRestrictions(): int
    {
        /** @var int */
        return $this->held('proxy_restrictions');
    }

    /**
     * The `{namespace}local` name of every other condition, in order.
     *
     * @return list<string>
     */
    public function otherConditions(): array
    {
        /** @var list<string> */
        return $this->held('other_conditions');
    }
}
