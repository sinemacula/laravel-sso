<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;

/**
 * How the application sends the browser to the identity provider (SSO-5.1): a
 * `redirect` to a URL, or a `post` of form fields to an action URL (an
 * HTTP-POST `AuthnRequest`, SSO-5.3). The application's controller turns it
 * into a response; `jsonSerialize()` is the `navigation` of SSO-12.5's start
 * response, `{type: redirect, url}` or `{type: post, url, fields}`.
 *
 * A navigation to an identity provider leads to an absolute `https` URL. One
 * back to the application itself, a discovery miss's fallback (SSO-3.5), leads
 * to the URL the application registered, which may be `http` on a loopback
 * address or a native application's private-use scheme, exactly as registered.
 *
 * Its URL and fields carry the flow's protocol values (an OIDC request's
 * `state`, `nonce` and `code_challenge`, a SAML form's `SAMLRequest` and
 * `RelayState`), so it holds them in `\SensitiveParameterValue` and gives them
 * only through `url()`, `fields()` and `jsonSerialize()`, which the start
 * response is built from. Every dump, PHP's own or Symfony's VarDumper behind
 * Laravel's dump helpers (which also lists private properties), shows the URL
 * with every query value and any fragment redacted, and a post's field names
 * with their values redacted.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Navigation implements \JsonSerializable
{
    /** @var string What a dump shows for each query value, fragment and field value. */
    private const string REDACTED = '[redacted]';

    /** @var \SensitiveParameterValue The URL redirected to, or the form's action. */
    private \SensitiveParameterValue $url;

    /** @var \SensitiveParameterValue The form's fields, by name; none for a redirect. */
    private \SensitiveParameterValue $fields;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Protocols\Enums\NavigationType  $type
     * @param  string  $url
     * @param  array<string, string>  $fields
     */
    private function __construct(

        /** Whether the browser is redirected or posts a form. */
        public NavigationType $type,

        // The URL redirected to, or the form's action; held wrapped.
        #[\SensitiveParameter]
        string $url,

        // The form's fields, by name; held wrapped.
        #[\SensitiveParameter]
        array $fields,
    ) {
        $this->url    = new \SensitiveParameterValue($url);
        $this->fields = new \SensitiveParameterValue($fields);
    }

    /**
     * What a dump shows: the type, the URL with every query value and any
     * fragment redacted, and the names of a post's fields, never their values.
     *
     * @return array{type: string, url: string, fields?: array<string, string>}
     */
    public function __debugInfo(): array
    {
        $navigation = ['type' => $this->type->value, 'url' => self::redactedUrl($this->url())];

        if ($this->isPost()) {
            $navigation['fields'] = array_fill_keys(array_keys($this->fields()), self::REDACTED);
        }

        return $navigation;
    }

    /**
     * Redirect the browser to the URL.
     *
     * @param  string  $url
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function redirect(#[\SensitiveParameter] string $url): self
    {
        return new self(NavigationType::REDIRECT, self::https($url), []);
    }

    /**
     * Redirect the browser back to a URL the application registered, such as
     * its discovery fallback: an exact redirect URI (`UrlSetting::redirect()`).
     *
     * @param  string  $url
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function toApplication(string $url): self
    {
        return new self(NavigationType::REDIRECT, UrlSetting::redirect('navigation', $url), []);
    }

    /**
     * Post the fields to the URL from a form.
     *
     * @param  string  $url
     * @param  array<array-key, mixed>  $fields
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function post(string $url, #[\SensitiveParameter] array $fields): self
    {
        $named = [];

        foreach ($fields as $name => $value) {

            if (!is_string($name) || $name === '' || !is_string($value)) {
                throw new \InvalidArgumentException('A posted form\'s fields are strings, each under a non-empty name.');
            }

            $named[$name] = $value;
        }

        return new self(NavigationType::POST, self::https($url), $named);
    }

    /**
     * Whether the browser is redirected.
     *
     * @return bool
     */
    public function isRedirect(): bool
    {
        return $this->type === NavigationType::REDIRECT;
    }

    /**
     * Whether the browser posts a form.
     *
     * @return bool
     */
    public function isPost(): bool
    {
        return $this->type === NavigationType::POST;
    }

    /**
     * The URL redirected to, or the form's action, whole.
     *
     * @return string
     */
    public function url(): string
    {
        /** @var string */
        return $this->url->getValue();
    }

    /**
     * The form's fields, by name, whole; none for a redirect.
     *
     * @return array<string, string>
     */
    public function fields(): array
    {
        /** @var array<string, string> */
        return $this->fields->getValue();
    }

    /**
     * The navigation as SSO-12.5's start response carries it: the type and the
     * URL, and the fields of a post, whole.
     *
     * @return array{type: string, url: string, fields?: array<string, string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $navigation = ['type' => $this->type->value, 'url' => $this->url()];

        if ($this->isPost()) {
            $navigation['fields'] = $this->fields();
        }

        return $navigation;
    }

    /**
     * The URL, once it is an absolute `https` URL.
     *
     * @param  string  $url
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private static function https(#[\SensitiveParameter] string $url): string
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host   = parse_url($url, PHP_URL_HOST);

        if (!is_string($scheme) || strtolower($scheme) !== 'https' || !is_string($host) || $host === '') {
            throw new \InvalidArgumentException('A navigation leads to an absolute https URL.');
        }

        return $url;
    }

    /**
     * The URL with the value of every query parameter, and any fragment,
     * redacted: its scheme, host, path and parameter names kept.
     *
     * @param  string  $url
     * @return string
     */
    private static function redactedUrl(#[\SensitiveParameter] string $url): string
    {
        $parts    = explode('#', $url);
        $address  = explode('?', $parts[0], 2);
        $redacted = $address[0];

        if (isset($address[1])) {
            $redacted .= '?' . implode('&', array_map(static fn (string $parameter): string => self::redactedParameter($parameter), explode('&', $address[1])));
        }

        return isset($parts[1]) ? $redacted . '#' . self::REDACTED : $redacted;
    }

    /**
     * The query parameter with its value redacted: a name with no value is kept
     * as it is.
     *
     * @param  string  $parameter
     * @return string
     */
    private static function redactedParameter(#[\SensitiveParameter] string $parameter): string
    {
        $name = strstr($parameter, '=', true);

        return $name === false ? $parameter : $name . '=' . self::REDACTED;
    }
}
