<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;

/**
 * How the application sends the browser to the identity provider (SSO-5.1): a
 * `redirect` to a URL, or a `post` of form fields to an action URL (an
 * HTTP-POST `AuthnRequest`, SSO-5.3). The application's controller turns it
 * into a response; `jsonSerialize()` is the `navigation` of SSO-12.5's start
 * response, `{type: redirect, url}` or `{type: post, url, fields}`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Navigation implements \JsonSerializable
{
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

        /** The URL redirected to, or the form's action. */
        public string $url,

        /** The form's fields, by name; none for a redirect. */
        public array $fields,
    ) {}

    /**
     * Redirect the browser to the URL.
     *
     * @param  string  $url
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function redirect(string $url): self
    {
        return new self(NavigationType::REDIRECT, self::url($url), []);
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
    public static function post(string $url, array $fields): self
    {
        $named = [];

        foreach ($fields as $name => $value) {

            if (!is_string($name) || $name === '' || !is_string($value)) {
                throw new \InvalidArgumentException('A posted form\'s fields are strings, each under a non-empty name.');
            }

            $named[$name] = $value;
        }

        return new self(NavigationType::POST, self::url($url), $named);
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
     * The navigation as SSO-12.5's start response carries it: the type and the
     * URL, and the fields of a post.
     *
     * @return array{type: string, url: string, fields?: array<string, string>}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        $navigation = ['type' => $this->type->value, 'url' => $this->url];

        if ($this->isPost()) {
            $navigation['fields'] = $this->fields;
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
    private static function url(string $url): string
    {
        $scheme = parse_url($url, PHP_URL_SCHEME);
        $host   = parse_url($url, PHP_URL_HOST);

        if (!is_string($scheme) || strtolower($scheme) !== 'https' || !is_string($host) || $host === '') {
            throw new \InvalidArgumentException('A navigation leads to an absolute https URL.');
        }

        return $url;
    }
}
