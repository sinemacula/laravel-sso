<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Messages;

use SineMacula\Laravel\Sso\Protocols\Saml2\Messages\Concerns\HoldsProviderValues;

/**
 * A SAML response's `Status` (SAML 2.0 Core §3.2.2.1), as the SAML adapter read
 * it: the top-level `StatusCode`, its first second-level code, and the
 * `StatusMessage`. The message is the identity provider's own text: it may be
 * logged only through the sanitiser and is never shown or put in an event
 * (SSO-5.7, SSO-6.9).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SamlStatus implements \JsonSerializable
{
    use HoldsProviderValues;

    /** @var string The status code of a successful response. */
    public const string SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';

    /**
     * Constructor.
     *
     * @param  string  $code
     * @param  ?string  $subCode
     * @param  ?string  $message
     */
    public function __construct(
        // The top-level status code
        string $code,
        // Its first second-level status code
        ?string $subCode = null,
        // The provider's status message
        #[\SensitiveParameter]
        ?string $message = null,
    ) {
        $this->hold(['code' => $code, 'sub_code' => $subCode, 'message' => $message]);
    }

    /**
     * The top-level `StatusCode`.
     *
     * @return string
     */
    public function code(): string
    {
        /** @var string */
        return $this->held('code');
    }

    /**
     * Whether the top-level code is success, compared exactly.
     *
     * @return bool
     */
    public function isSuccess(): bool
    {
        return $this->code() === self::SUCCESS;
    }

    /**
     * The first second-level `StatusCode`, or `null` when absent.
     *
     * @return ?string
     */
    public function subCode(): ?string
    {
        /** @var ?string */
        return $this->held('sub_code');
    }

    /**
     * The `StatusMessage`, the provider's own text, or `null` when absent.
     *
     * @return ?string
     */
    public function message(): ?string
    {
        /** @var ?string */
        return $this->held('message');
    }
}
