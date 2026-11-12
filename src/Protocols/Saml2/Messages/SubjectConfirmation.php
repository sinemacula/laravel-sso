<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * One `SubjectConfirmation` of a verified assertion, unjudged.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SubjectConfirmation implements \JsonSerializable
{
    use HoldsProviderValues;

    /** @var string The bearer confirmation method. */
    public const string BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

    /**
     * Constructor.
     *
     * @param  string  $method
     * @param  bool  $hasData
     * @param  ?\Carbon\CarbonImmutable  $notBefore
     * @param  ?\Carbon\CarbonImmutable  $notOnOrAfter
     * @param  ?string  $recipient
     * @param  ?string  $inResponseTo
     * @param  ?string  $address
     */
    public function __construct(
        // The confirmation method
        string $method,
        // Whether the confirmation carries its data element
        bool $hasData = false,
        // The instant the data is valid from
        ?CarbonImmutable $notBefore = null,
        // The instant the data stops being valid
        ?CarbonImmutable $notOnOrAfter = null,
        // The recipient the data names
        ?string $recipient = null,
        // The request the data answers
        ?string $inResponseTo = null,
        // The address the data names
        #[\SensitiveParameter]
        ?string $address = null,
    ) {
        $this->hold([
            'method'          => $method,
            'has_data'        => $hasData,
            'not_before'      => $notBefore,
            'not_on_or_after' => $notOnOrAfter,
            'recipient'       => $recipient,
            'in_response_to'  => $inResponseTo,
            'address'         => $address,
        ]);
    }

    /**
     * The `Method` attribute.
     *
     * @return string
     */
    public function method(): string
    {
        /** @var string */
        return $this->held('method');
    }

    /**
     * Whether the method is bearer, compared exactly.
     *
     * @return bool
     */
    public function isBearer(): bool
    {
        return $this->method() === self::BEARER;
    }

    /**
     * Whether a `SubjectConfirmationData` element is present.
     *
     * @return bool
     */
    public function hasData(): bool
    {
        return $this->held('has_data') === true;
    }

    /**
     * The data's `NotBefore`, or `null` when absent.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function notBefore(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->held('not_before');
    }

    /**
     * The data's `NotOnOrAfter`, or `null` when absent.
     *
     * @return ?\Carbon\CarbonImmutable
     */
    public function notOnOrAfter(): ?CarbonImmutable
    {
        /** @var ?\Carbon\CarbonImmutable */
        return $this->held('not_on_or_after');
    }

    /**
     * The data's `Recipient`, or `null` when absent.
     *
     * @return ?string
     */
    public function recipient(): ?string
    {
        /** @var ?string */
        return $this->held('recipient');
    }

    /**
     * The data's `InResponseTo`, or `null` when absent.
     *
     * @return ?string
     */
    public function inResponseTo(): ?string
    {
        /** @var ?string */
        return $this->held('in_response_to');
    }

    /**
     * The data's `Address`, or `null` when absent.
     *
     * @return ?string
     */
    public function address(): ?string
    {
        /** @var ?string */
        return $this->held('address');
    }
}
