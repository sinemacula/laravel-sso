<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * One `AuthnStatement` of a verified assertion.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class AuthnStatement implements \JsonSerializable
{
    use HoldsProviderValues;

    /**
     * Constructor.
     *
     * @param  \Carbon\CarbonImmutable  $authnInstant
     * @param  ?string  $sessionIndex
     * @param  ?\Carbon\CarbonImmutable  $sessionNotOnOrAfter
     * @param  ?string  $contextClassRef
     */
    public function __construct(
        // The `AuthnInstant` attribute
        CarbonImmutable $authnInstant,
        // The `SessionIndex` attribute
        #[\SensitiveParameter]
        ?string $sessionIndex = null,
        // The `SessionNotOnOrAfter` attribute
        ?CarbonImmutable $sessionNotOnOrAfter = null,
        // The `AuthnContextClassRef` of its context
        ?string $contextClassRef = null,
    ) {
        $this->hold([
            'authn_instant'           => $authnInstant,
            'session_index'           => $sessionIndex,
            'session_not_on_or_after' => $sessionNotOnOrAfter,
            'context_class_ref'       => $contextClassRef,
        ]);
    }

    /**
     * The `AuthnInstant` attribute.
     *
     * @return \Carbon\CarbonImmutable
     */
    public function authnInstant(): CarbonImmutable
    {
        /** @var \Carbon\CarbonImmutable */
        return $this->held('authn_instant');
    }

    /**
     * The `SessionIndex` attribute, or `null` when absent.
     *
     * @return ?string
     */
    public function sessionIndex(): ?string
    {
        /** @var ?string */
        return $this->held('session_index');
    }

    /**
     * The `SessionNotOnOrAfter` attribute, or `null` when absent.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function sessionNotOnOrAfter(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->held('session_not_on_or_after');
    }

    /**
     * The `AuthnContextClassRef` of its context, or `null` when absent.
     *
     * @return ?string
     */
    public function contextClassRef(): ?string
    {
        /** @var ?string */
        return $this->held('context_class_ref');
    }
}
