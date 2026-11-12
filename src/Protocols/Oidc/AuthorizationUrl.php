<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Protocols\StartRequest;
use SineMacula\Laravel\Sso\Secrets\Secret;

/**
 * Builds the authorisation code request URL. No `response_mode` is sent, so the
 * provider answers in query mode, the only one the callback accepts.
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
     * The URL, or `null` when the endpoint has a fragment or its query names a
     * parameter the request sets or the flow controls.
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
     * The `max_age` and `prompt` for the purpose.
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
     * The extra parameters, skipping non-strings and any name the flow controls
     * or the request sets, in any case.
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
     * Whether the endpoint has a fragment or its query names a taken parameter,
     * so the start is refused rather than a parameter overridden.
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
     * The lower-case names the parameters set and the flow controls.
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
     * The decoded, lower-case parameter names of the endpoint's own query.
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
     * The separator before the request's query: `?`, `&`, or nothing when the
     * endpoint already ends with one.
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
     * The S256 challenge of the PKCE verifier.
     *
     * @param  \SineMacula\Laravel\Sso\Secrets\Secret  $verifier
     * @return string
     */
    private static function challenge(#[\SensitiveParameter] Secret $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier->reveal(), true)), '+/', '-_'), '=');
    }

    /**
     * Require a value the start pipeline makes for every OIDC start.
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
