<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;

/**
 * One outbound request, built through its purpose's named constructor so it
 * carries only the credential that purpose allows. The fetcher checks the URL.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FetchRequest
{
    /** @var list<string> Form fields only the fetcher sets, from the request's client authentication. */
    public const array RESERVED_FORM_FIELDS = ['client_id', 'client_secret', 'client_assertion', 'client_assertion_type'];

    /** @var \SensitiveParameterValue The form fields of a token request. */
    private \SensitiveParameterValue $form;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose  $purpose
     * @param  string  $url
     * @param  array<string, string>  $form
     * @param  ?\SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @param  ?int  $maxBytes
     * @param  ?int  $timeoutSeconds
     *
     * @throws \InvalidArgumentException
     */
    private function __construct(

        /** What the request is for. */
        public FetchPurpose $purpose,

        /** The absolute URL to fetch, as entered or supplied. */
        public string $url,

        // Not promoted: held wrapped, so no dump, export or array cast shows it
        #[\SensitiveParameter]
        array $form = [],

        /** The one credential the request carries, if its purpose takes one. */
        public ?FetchCredentials $credentials = null,

        /** The response size cap in bytes, or `null` for the fetcher's. */
        public ?int $maxBytes = null,

        /** The whole request timeout, or `null` for the fetcher's. */
        public ?int $timeoutSeconds = null,
    ) {
        if ($maxBytes !== null && $maxBytes < 1) {
            throw new \InvalidArgumentException('A request\'s own size cap is at least one byte.');
        }

        if ($timeoutSeconds !== null && $timeoutSeconds < 1) {
            throw new \InvalidArgumentException('A request\'s own timeout is at least one second.');
        }

        $this->form = new \SensitiveParameterValue($form);
    }

    /**
     * Show everything but the form values and the credential's secret.
     *
     * @return array<string, mixed>
     */
    public function __debugInfo(): array
    {
        return [
            'purpose'     => $this->purpose->value,
            'url'         => $this->url,
            'form'        => array_keys($this->form()),
            'credentials' => $this->credentials?->kind->value,
            'max_bytes'   => $this->maxBytes,
            'timeout'     => $this->timeoutSeconds,
        ];
    }

    /**
     * Refuse to be serialised; a request lives only while it is sent.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('Outbound requests cannot be serialised.');
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
        throw new \LogicException('Outbound requests cannot be unserialised.');
    }

    /**
     * Fetch a SAML identity provider's metadata, with no credential.
     *
     * @param  string  $url
     * @param  ?int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function metadata(string $url, ?int $maxBytes = null): self
    {
        return new self(FetchPurpose::METADATA, $url, maxBytes: $maxBytes);
    }

    /**
     * Fetch an OpenID provider's discovery document, with no credential.
     *
     * @param  string  $url
     * @param  ?int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function discovery(string $url, ?int $maxBytes = null): self
    {
        return new self(FetchPurpose::DISCOVERY, $url, maxBytes: $maxBytes);
    }

    /**
     * Fetch an OpenID provider's JSON Web Key Set, with no credential.
     *
     * @param  string  $url
     * @param  ?int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function jwks(string $url, ?int $maxBytes = null): self
    {
        return new self(FetchPurpose::JWKS, $url, maxBytes: $maxBytes);
    }

    /**
     * Post a token request authenticated by the client authentication alone;
     * the form may not set a reserved field.
     *
     * @param  string  $url
     * @param  array<string, string>  $form
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @param  ?int  $timeoutSeconds
     * @param  ?int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function token(string $url, #[\SensitiveParameter] array $form, FetchCredentials $credentials, ?int $timeoutSeconds = null, ?int $maxBytes = null): self
    {
        if (!$credentials->kind->isClientAuthentication()) {
            throw new \InvalidArgumentException('A token request is authenticated by a client authentication, not an access token.');
        }

        $reserved = array_intersect(array_keys($form), self::RESERVED_FORM_FIELDS);

        if ($reserved !== []) {
            throw new \InvalidArgumentException(sprintf('A token request\'s form may not set [%s]: the connection\'s client authentication sets them.', implode(', ', $reserved)));
        }

        return new self(FetchPurpose::TOKEN, $url, $form, $credentials, $maxBytes, $timeoutSeconds);
    }

    /**
     * Fetch the UserInfo response with the access token alone.
     *
     * @param  string  $url
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $accessToken
     * @param  ?int  $timeoutSeconds
     * @param  ?int  $maxBytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function userInfo(string $url, FetchCredentials $accessToken, ?int $timeoutSeconds = null, ?int $maxBytes = null): self
    {
        if ($accessToken->kind->isClientAuthentication()) {
            throw new \InvalidArgumentException('A UserInfo request carries the access token only, never the client authentication.');
        }

        return new self(FetchPurpose::USERINFO, $url, credentials: $accessToken, maxBytes: $maxBytes, timeoutSeconds: $timeoutSeconds);
    }

    /**
     * The HTTP method: `POST` for a token request, otherwise `GET`.
     *
     * @return string
     */
    public function method(): string
    {
        return $this->purpose === FetchPurpose::TOKEN ? 'POST' : 'GET';
    }

    /**
     * The token request's form fields, for the fetcher only; `[]` otherwise.
     *
     * @return array<string, string>
     */
    public function form(): array
    {
        /** @var array<string, string> */
        return $this->form->getValue();
    }
}
