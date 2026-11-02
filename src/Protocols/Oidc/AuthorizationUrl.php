<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * The URL an OpenID Connect authorisation code request sends the browser to
 * (SSO-5.4, SSO-5.10, SSO-2.4, `docs/design/oidc-requests.md`): the
 * connection's authorisation endpoint with the request's parameters appended,
 * in this order:
 *
 * - `response_type=code`, the only response type;
 * - `client_id`, the connection's;
 * - `redirect_uri`, the connection's callback exactly as the endpoint resolver
 *   built it (SSO-5.5);
 * - `scope`, the connection's scopes joined by single spaces, in stored order;
 * - `state`, the flow's protocol state, never the public reference (SSO-5.2);
 * - `nonce`;
 * - `code_challenge`, the S256 challenge of the PKCE verifier (RFC 7636 §4.2,
 *   as `Flows\ProtocolState` computes it), and `code_challenge_method=S256`;
 * - `max_age`: `0` for a `reauthenticate`, else the connection's when set;
 * - `prompt=login` for a `reauthenticate` (SSO-5.10);
 * - the connection's extra parameters, in stored order.
 *
 * No `response_mode` is sent, so the provider answers in the code flow's
 * default query mode, the only one the callback accepts, and neither `request`
 * nor `request_uri` is ever sent. The settings allow only listed extra
 * parameters and refuse any the flow controls; this checks again, and leaves
 * out an extra parameter whose name, in any case, the flow controls
 * (`OidcSettings::RESERVED_PARAMETERS`) or the request already sets (`prompt`
 * for a `reauthenticate`, `max_age` when it is sent), or whose value is not a
 * string, so an extra parameter never sets or overrides one the flow controls.
 *
 * The query is encoded per RFC 3986 (`PHP_QUERY_RFC3986`). An endpoint that has
 * a query keeps it, and the request's is appended after `&`. When that query
 * names, in any case, a parameter the request sets or the flow controls, or the
 * endpoint has a fragment, there is no URL: the start is refused rather than a
 * parameter overridden or sent twice.
 *
 * A `StartRequest` without a nonce or a PKCE verifier is the start pipeline's
 * bug, a `LogicException`. Nothing here keeps, logs or reports a value, and no
 * exception names one.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class AuthorizationUrl
{
    /** @var string The only response type sent: the authorisation code flow. */
    private const string RESPONSE_TYPE = 'code';

    /** @var string The only PKCE challenge method sent. */
    private const string CHALLENGE_METHOD = 'S256';

    /** @var string The `prompt` a `reauthenticate` sends, whatever else is configured. */
    private const string REAUTHENTICATE_PROMPT = 'login';

    /** @var string The `max_age` a `reauthenticate` sends, whatever else is configured. */
    private const string REAUTHENTICATE_MAX_AGE = '0';

    /** @var string The parameter `max_age`. */
    private const string MAX_AGE = 'max_age';

    /** @var string The parameter `prompt`. */
    private const string PROMPT = 'prompt';

    /**
     * The URL of the request, or `null` when the endpoint's own query names a
     * parameter the request sets or the flow controls, or the endpoint has a
     * fragment.
     *
     * @param  string  $endpoint
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @param  string  $redirectUri
     * @return ?string
     *
     * @throws \LogicException
     */
    public static function build(string $endpoint, OidcOptions $options, StartRequest $request, string $redirectUri): ?string
    {
        $parameters = self::parameters($options, $request, $redirectUri);

        if (self::conflicts($endpoint, $parameters)) {
            return null;
        }

        return $endpoint . self::separator($endpoint) . http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }

    /**
     * The request's parameters, in the order they are sent.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Protocols\StartRequest  $request
     * @param  string  $redirectUri
     * @return array<string, string>
     *
     * @throws \LogicException
     */
    private static function parameters(OidcOptions $options, StartRequest $request, string $redirectUri): array
    {
        $parameters = [
            'response_type'         => self::RESPONSE_TYPE,
            'client_id'             => $options->clientId(),
            'redirect_uri'          => $redirectUri,
            'scope'                 => implode(' ', $options->scopes()),
            'state'                 => $request->state->reveal(),
            'nonce'                 => self::required($request->nonce, 'nonce')->reveal(),
            'code_challenge'        => self::challenge(self::required($request->codeVerifier, 'PKCE verifier')),
            'code_challenge_method' => self::CHALLENGE_METHOD,
            ...self::freshness($options, $request->purpose),
        ];

        return [...$parameters, ...self::extras($options->extraParameters(), $parameters)];
    }

    /**
     * The `max_age` and `prompt` the purpose sends: `0` and `login` for a
     * `reauthenticate`, else the connection's `max_age` when it has one.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcOptions  $options
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @return array<string, string>
     */
    private static function freshness(OidcOptions $options, Purpose $purpose): array
    {
        if ($purpose === Purpose::REAUTHENTICATE) {
            return [self::MAX_AGE => self::REAUTHENTICATE_MAX_AGE, self::PROMPT => self::REAUTHENTICATE_PROMPT];
        }

        $maxAge = $options->maxAge();

        return $maxAge === null ? [] : [self::MAX_AGE => (string) $maxAge];
    }

    /**
     * The extra parameters sent, in their stored order: each a string value
     * under a name that, in any case, neither the flow controls nor the request
     * already sets.
     *
     * @param  array<array-key, mixed>  $extra
     * @param  array<string, string>  $parameters
     * @return array<string, string>
     */
    private static function extras(array $extra, #[\SensitiveParameter] array $parameters): array
    {
        $taken = self::taken($parameters);
        $sent  = [];

        foreach ($extra as $name => $value) {
            if (!is_string($name) || !is_string($value) || isset($taken[strtolower($name)])) {
                continue;
            }

            $sent[$name] = $value;
        }

        return $sent;
    }

    /**
     * Whether the endpoint cannot carry the request: it has a fragment, or its
     * own query names, in any case, a parameter the request sets or the flow
     * controls.
     *
     * @param  string  $endpoint
     * @param  array<string, string>  $parameters
     * @return bool
     */
    private static function conflicts(string $endpoint, #[\SensitiveParameter] array $parameters): bool
    {
        if (str_contains($endpoint, '#')) {
            return true;
        }

        $taken = self::taken($parameters);

        foreach (self::queryNames($endpoint) as $name) {
            if (isset($taken[$name])) {
                return true;
            }
        }

        return false;
    }

    /**
     * The names, in lower case, the parameters set and the flow controls.
     *
     * @param  array<string, string>  $parameters
     * @return array<string, true>
     */
    private static function taken(#[\SensitiveParameter] array $parameters): array
    {
        $names = [...OidcSettings::RESERVED_PARAMETERS, ...array_map(strtolower(...), array_keys($parameters))];

        return array_fill_keys($names, true);
    }

    /**
     * The name of each parameter of the endpoint's own query, decoded and in
     * lower case.
     *
     * @param  string  $endpoint
     * @return list<string>
     */
    private static function queryNames(string $endpoint): array
    {
        $query = explode('?', $endpoint, 2)[1] ?? '';

        return array_map(
            static fn (string $parameter): string => strtolower(urldecode(explode('=', $parameter)[0])),
            explode('&', $query),
        );
    }

    /**
     * What joins the endpoint and the request's query: `?`, or `&` when the
     * endpoint has a query already, or nothing when it ends with either.
     *
     * @param  string  $endpoint
     * @return string
     */
    private static function separator(string $endpoint): string
    {
        return match (true) {
            !str_contains($endpoint, '?')                                => '?',
            str_ends_with($endpoint, '?'), str_ends_with($endpoint, '&') => '',
            default                                                      => '&',
        };
    }

    /**
     * The S256 challenge of the PKCE verifier: `BASE64URL(SHA-256(verifier))`
     * without padding.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $verifier
     * @return string
     */
    private static function challenge(#[\SensitiveParameter] Secret $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier->reveal(), true)), '+/', '-_'), '=');
    }

    /**
     * The value the start pipeline makes for every OIDC start.
     *
     * @param  ?\SineMacula\Laravel\Sso\Secrets\Secret  $value
     * @param  string  $what
     * @return \SineMacula\Laravel\Sso\Secrets\Secret
     *
     * @throws \LogicException
     */
    private static function required(#[\SensitiveParameter] ?Secret $value, string $what): Secret
    {
        return $value ?? throw new \LogicException(sprintf('An OIDC start is given a %s; the start pipeline makes one for every start.', $what));
    }
}
