<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\Contracts\SecretEncrypter;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\RequestReference;
use SineMacula\Laravel\Sso\Secrets\ConstantTime;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * The consumed authorisation request a driver validates a response against. The
 * PKCE verifier stays encrypted until `codeVerifier()` is called.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConsumedRequest
{
    /** @var ?\SensitiveParameterValue A `\Closure(): string` decrypting the PKCE verifier. */
    private ?\SensitiveParameterValue $codeVerifier;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $application
     * @param  \SineMacula\Laravel\Sso\Flows\RequestReference  $reference
     * @param  \Carbon\CarbonImmutable  $startedAt
     * @param  ?string  $expectedIssuer
     * @param  bool  $issuerRequired
     * @param  ?string  $samlRequestId
     * @param  ?string  $nonceDigest
     * @param  ?string  $codeVerifier
     * @param  ?\SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** What the flow is for. */
        public Purpose $purpose,

        /** The application the flow is for. */
        public string $application,

        /** The request's public reference. */
        public RequestReference $reference,

        /** When the request started; a reauthentication must not predate it. */
        public CarbonImmutable $startedAt,

        /** The issuer the response must come from, as the request recorded it. */
        public ?string $expectedIssuer = null,

        /** Whether the response must carry `iss` (RFC 9207). */
        public bool $issuerRequired = false,

        /** The SAML `AuthnRequest` id `InResponseTo` must equal. */
        public ?string $samlRequestId = null,

        /** The lower-case hex SHA-256 digest of the OIDC nonce. */
        private ?string $nonceDigest = null,

        // Not promoted: the encrypted PKCE verifier, held wrapped
        #[\SensitiveParameter]
        ?string $codeVerifier = null,

        // Not promoted: captured by the decrypting closure
        ?SecretEncrypter $encrypter = null,
    ) {
        $this->codeVerifier = $codeVerifier === null ? null : new \SensitiveParameterValue(self::decryption($codeVerifier, $encrypter));
    }

    /**
     * Show the request without the nonce digest or the PKCE verifier.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'purpose'         => $this->purpose->value,
            'application'     => $this->application,
            'reference'       => $this->reference->value,
            'expected_issuer' => $this->expectedIssuer,
            'issuer_required' => $this->issuerRequired,
            'saml_request_id' => $this->samlRequestId,
            'nonce'           => $this->nonceDigest  === null ? null : '[redacted]',
            'code_verifier'   => $this->codeVerifier === null ? null : '[redacted]',
        ];
    }

    /**
     * Refuse to be serialised; it lives only for its completion.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A consumed authorisation request cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A consumed authorisation request cannot be unserialised.');
    }

    /**
     * The PKCE verifier, decrypted afresh on each call; `null` when there is
     * none.
     *
     * @return ?\SineMacula\Laravel\Sso\Secrets\Secret
     */
    public function codeVerifier(): ?Secret
    {
        /** @var ?\Closure(): string $decrypt */
        $decrypt = $this->codeVerifier?->getValue();

        return $decrypt === null ? null : new Secret($decrypt());
    }

    /**
     * Whether the nonce matches the stored digest, in constant time.
     *
     * @param  string  $nonce
     * @return bool
     */
    public function isNonce(#[\SensitiveParameter] string $nonce): bool
    {
        return $this->nonceDigest !== null && ConstantTime::matchesDigest($this->nonceDigest, $nonce);
    }

    /**
     * A closure that decrypts the PKCE verifier when called.
     *
     * @param  string  $ciphertext
     * @param  ?\SineMacula\Laravel\Sso\Contracts\SecretEncrypter  $encrypter
     * @return \Closure(): string
     *
     * @throws \InvalidArgumentException
     */
    private static function decryption(#[\SensitiveParameter] string $ciphertext, ?SecretEncrypter $encrypter): \Closure
    {
        if ($encrypter === null) {
            throw new \InvalidArgumentException('An encrypted PKCE verifier is given with the encrypter that decrypts it.');
        }

        return static fn (): string => $encrypter->decrypt($ciphertext);
    }
}
