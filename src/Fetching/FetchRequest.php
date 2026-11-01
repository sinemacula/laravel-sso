<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Fetching;

use SineMacula\Laravel\Sso\Fetching\Enums\FetchPurpose;

/**
 * One outbound request (SSO-2.9): its purpose, the URL an administrator entered
 * or metadata or discovery supplied, and, for a token request, its form fields
 * and client authentication, or, for UserInfo, its access token.
 *
 * Built only through the named constructor of its purpose, which pairs it with
 * the only credential that purpose may carry: none for metadata, discovery and
 * a JWKS, a client authentication for a token request, and an access token for
 * UserInfo. A token request's form may not carry a client authentication of its
 * own (`RESERVED_FORM_FIELDS`), so it is authenticated by exactly one method,
 * the connection's (SSO-7.2). The URL is not checked here: whether it may be
 * fetched is the fetcher's answer, a refusal, never an exception.
 *
 * The form (a token request's code and PKCE verifier) is held in a
 * `\SensitiveParameterValue`, so no dump, export or array cast shows a value of
 * it, and the request refuses to be serialised.
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
     */
    private function __construct(

        /** What the request is for. */
        public FetchPurpose $purpose,

        /** The absolute URL to fetch, as entered or supplied. */
        public string $url,

        // Not promoted: held wrapped, so no dump, export or array cast shows a
        // value of it
        #[\SensitiveParameter]
        array $form = [],

        /** The one credential the request carries, if its purpose takes one. */
        public ?FetchCredentials $credentials = null,
    ) {
        $this->form = new \SensitiveParameterValue($form);
    }

    /**
     * What a dump shows: the purpose, the URL, the names of the form fields and
     * the credential's kind, never a value of the form or the credential.
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
        ];
    }

    /**
     * Refuse to be serialised: a request lives only while it is sent.
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
     * @return self
     */
    public static function metadata(string $url): self
    {
        return new self(FetchPurpose::METADATA, $url);
    }

    /**
     * Fetch an OpenID provider's discovery document, with no credential.
     *
     * @param  string  $url
     * @return self
     */
    public static function discovery(string $url): self
    {
        return new self(FetchPurpose::DISCOVERY, $url);
    }

    /**
     * Fetch an OpenID provider's JSON Web Key Set, with no credential.
     *
     * @param  string  $url
     * @return self
     */
    public static function jwks(string $url): self
    {
        return new self(FetchPurpose::JWKS, $url);
    }

    /**
     * Post a form-encoded token request, authenticated by the connection's
     * client authentication alone.
     *
     * @param  string  $url
     * @param  array<string, string>  $form
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $credentials
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function token(string $url, #[\SensitiveParameter] array $form, FetchCredentials $credentials): self
    {
        if (!$credentials->kind->isClientAuthentication()) {
            throw new \InvalidArgumentException('A token request is authenticated by a client authentication, not an access token.');
        }

        $reserved = array_intersect(array_keys($form), self::RESERVED_FORM_FIELDS);

        if ($reserved !== []) {
            throw new \InvalidArgumentException(sprintf('A token request\'s form may not set [%s]: the connection\'s client authentication sets them.', implode(', ', $reserved)));
        }

        return new self(FetchPurpose::TOKEN, $url, $form, $credentials);
    }

    /**
     * Fetch the UserInfo response with the access token alone.
     *
     * @param  string  $url
     * @param  \SineMacula\Laravel\Sso\Fetching\FetchCredentials  $accessToken
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function userInfo(string $url, FetchCredentials $accessToken): self
    {
        if ($accessToken->kind->isClientAuthentication()) {
            throw new \InvalidArgumentException('A UserInfo request carries the access token only, never the client authentication.');
        }

        return new self(FetchPurpose::USERINFO, $url, credentials: $accessToken);
    }

    /**
     * The HTTP method: `POST` for a token request, `GET` for every other.
     *
     * @return string
     */
    public function method(): string
    {
        return $this->purpose === FetchPurpose::TOKEN ? 'POST' : 'GET';
    }

    /**
     * The form fields of a token request, for the fetcher to send and for
     * nothing else; `[]` for every other purpose.
     *
     * @return array<string, string>
     */
    public function form(): array
    {
        /** @var array<string, string> */
        return $this->form->getValue();
    }
}
