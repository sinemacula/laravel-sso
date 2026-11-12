<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols;

use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Protocols\Enums\NavigationType;

/**
 * A redirect or form post that sends the browser on. The URL and fields carry
 * protocol state, so dumps redact query values, fragments and field values.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Navigation implements \JsonSerializable
{
    /** @var string Placeholder for each redacted value in a dump. */
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

        // Held wrapped, so not promoted.
        #[\SensitiveParameter]
        string $url,

        // Held wrapped, so not promoted.
        #[\SensitiveParameter]
        array $fields,
    ) {
        $this->url    = new \SensitiveParameterValue($url);
        $this->fields = new \SensitiveParameterValue($fields);
    }

    /**
     * Show the type, the redacted URL and the field names, never a value.
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
     * Redirect the browser to a URL the application registered, which may be
     * loopback `http` or a private-use scheme.
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
     * The URL redirected to, or the form's action, unredacted.
     *
     * @return string
     */
    public function url(): string
    {
        /** @var string */
        return $this->url->getValue();
    }

    /**
     * The form's fields, unredacted; empty for a redirect.
     *
     * @return array<string, string>
     */
    public function fields(): array
    {
        /** @var array<string, string> */
        return $this->fields->getValue();
    }

    /**
     * The unredacted `navigation` of the start response.
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
     * The URL, if it is an absolute `https` URL.
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
     * The URL with every query value and any fragment redacted.
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
     * The query parameter with its value redacted; a bare name is kept.
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
