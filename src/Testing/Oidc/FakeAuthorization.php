<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * One authorisation the fake OpenID provider granted: the request parameters,
 * the issued code and the tokens its token endpoint returns for it.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FakeAuthorization
{
    /**
     * Constructor.
     *
     * @param  array<string, string>  $parameters
     * @param  string  $code
     * @param  string  $issuer
     * @param  \SineMacula\Laravel\Sso\Testing\Oidc\FakeIdToken|string  $idToken
     * @param  string  $accessToken
     */
    public function __construct(

        /** The authorisation request's parameters, as its URL carried them. */
        private array $parameters,

        /** The authorisation code issued. */
        public string $code,

        /** The provider's issuer, the callback's `iss`. */
        public string $issuer,

        /** The ID token returned for the code, or its raw text. */
        #[\SensitiveParameter]
        public FakeIdToken|string $idToken,

        /** The access token returned for the code. */
        #[\SensitiveParameter]
        public string $accessToken,
    ) {}

    /**
     * The authorisation request's parameters.
     *
     * @return array<string, string>
     */
    public function parameters(): array
    {
        return $this->parameters;
    }

    /**
     * One of the authorisation request's parameters, or `null`.
     *
     * @param  string  $name
     * @return ?string
     */
    public function parameter(string $name): ?string
    {
        return $this->parameters[$name] ?? null;
    }

    /**
     * The callback's raw query string of `code`, `state` and `iss`, with the
     * overrides applied; a `null` removes a parameter.
     *
     * @param  array<string, ?string>  $overrides
     * @return string
     */
    public function query(array $overrides = []): string
    {
        $parameters = ['code' => $this->code, 'state' => $this->parameter('state'), 'iss' => $this->issuer];

        return self::encoded([...$parameters, ...$overrides]);
    }

    /**
     * An error response's raw query string, with the overrides applied.
     *
     * @param  string  $error
     * @param  ?string  $description
     * @param  array<string, ?string>  $overrides
     * @return string
     */
    public function errorQuery(string $error, ?string $description = null, array $overrides = []): string
    {
        $parameters = ['error' => $error, 'error_description' => $description, 'state' => $this->parameter('state'), 'iss' => $this->issuer];

        return self::encoded([...$parameters, ...$overrides]);
    }

    /**
     * Build a raw query string from ordered pairs, so a name may repeat.
     *
     * @param  list<array{0: string, 1: string}>  $pairs
     * @return string
     */
    public static function repeated(array $pairs): string
    {
        return implode('&', array_map(static fn (array $pair): string => rawurlencode($pair[0]) . '=' . rawurlencode($pair[1]), $pairs));
    }

    /**
     * Encode the non-null parameters as a query string.
     *
     * @param  array<string, ?string>  $parameters
     * @return string
     */
    private static function encoded(array $parameters): string
    {
        return http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
