<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Testing\Oidc;

/**
 * One authorisation the fake OpenID provider granted (SSO-12.4): what the
 * package's authorisation request asked for (`parameters()`, as the URL carried
 * them), the code it issued, and the ID token and access token its token
 * endpoint answers that code with.
 *
 * `query()` is the callback's raw query string, `code`, `state` and the RFC
 * 9207 `iss` by default, each overridable or removed (`null`); `errorQuery()` is
 * an error response's. `repeated()` builds a raw query from pairs, so a test
 * can repeat a parameter, give it as an array (`state[]`) or make it long.
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

        /** The ID token the token endpoint answers the code with, or its raw text. */
        #[\SensitiveParameter]
        public FakeIdToken|string $idToken,

        /** The access token the token endpoint answers the code with. */
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
     * The callback's raw query string: `code`, `state` and `iss`, with the
     * overrides laid over them (a `null` removes one).
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
     * An error response's raw query string: `error`, its description when
     * given, `state` and `iss`, with the overrides laid over them.
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
     * A raw query string of the pairs, in order, each name and value
     * percent-encoded as given, so a name may repeat.
     *
     * @param  list<array{0: string, 1: string}>  $pairs
     * @return string
     */
    public static function repeated(array $pairs): string
    {
        return implode('&', array_map(static fn (array $pair): string => rawurlencode($pair[0]) . '=' . rawurlencode($pair[1]), $pairs));
    }

    /**
     * The parameters given a value, encoded as a query string.
     *
     * @param  array<string, ?string>  $parameters
     * @return string
     */
    private static function encoded(array $parameters): string
    {
        return http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }
}
