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
 * The authorisation request a response was correlated with, as the completion
 * pipeline consumed it (SSO-5.1, SSO-6.6, SSO-7.1), given to the protocol
 * driver to validate the response against: what the flow is for, the
 * application, the public reference, when it started, the issuer it expects and
 * whether that issuer must return `iss` (SSO-7.1), the SAML `AuthnRequest` id
 * `InResponseTo` must equal, the nonce's digest, and the PKCE verifier the
 * package uses with the identity provider (SSO-5.4).
 *
 * It is consumed before the driver sees it, so it is never consumed again,
 * whether the response passes or fails. It keeps the PKCE verifier as the
 * request stored it, encrypted, and decrypts it into a `Secrets\Secret` only
 * when the driver asks for it (`codeVerifier()`) to build the token request,
 * afresh on each call and keeping nothing, so a completion whose driver never
 * asks (a SAML one) never decrypts it, and the plaintext never lives in the
 * completion's state. The ciphertext and the encrypter are held in a
 * `\SensitiveParameterValue`, and the nonce only as a digest, compared in
 * constant time; a dump shows none of them, and it refuses to be serialised or
 * unserialised.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ConsumedRequest
{
    /** @var ?\SensitiveParameterValue What decrypts the PKCE verifier, a `\Closure(): string`, when the request keeps one. */
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

        /** When the request started, by the package's clock (a `reauthenticate` result's authentication time must not be earlier). */
        public CarbonImmutable $startedAt,

        /** The issuer the response must come from, as the request recorded it. */
        public ?string $expectedIssuer = null,

        /** Whether the response must carry `iss` (RFC 9207). */
        public bool $issuerRequired = false,

        /** The SAML `AuthnRequest` id `InResponseTo` must equal. */
        public ?string $samlRequestId = null,

        /** The lower-case hex SHA-256 digest of the OIDC nonce. */
        private ?string $nonceDigest = null,

        // Not promoted: the PKCE verifier, encrypted, held wrapped
        #[\SensitiveParameter]
        ?string $codeVerifier = null,

        // Not promoted: decrypts it only when the driver asks
        ?SecretEncrypter $encrypter = null,
    ) {
        $this->codeVerifier = $codeVerifier === null ? null : new \SensitiveParameterValue(self::decryption($codeVerifier, $encrypter));
    }

    /**
     * What a dump shows: never the nonce's digest or the PKCE verifier.
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
     * Refuse to be serialised: the request is consumed for the completion that
     * consumed it and lives no longer.
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
     * The PKCE verifier the package uses with the identity provider, decrypted
     * now, for the token request and for nothing else; `null` when the request
     * keeps none. A ciphertext no key decrypts propagates (SSO-11.4).
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
     * Whether the nonce is the one the request stored, compared in constant
     * time; never when the request stored none.
     *
     * @param  string  $nonce
     * @return bool
     */
    public function isNonce(#[\SensitiveParameter] string $nonce): bool
    {
        return $this->nonceDigest !== null && ConstantTime::matchesDigest($this->nonceDigest, $nonce);
    }

    /**
     * What decrypts the PKCE verifier's ciphertext through the encrypter, once
     * it is asked to. A ciphertext with no encrypter is application code's
     * mistake.
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
