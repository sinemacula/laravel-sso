<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Applications;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery;
use SineMacula\Laravel\Sso\Config\BooleanSetting;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\Config\UrlSetting;

/**
 * An application registered under `sso.applications.<name>`.
 *
 * Its one redirect URI is used exactly as configured; nothing in a request can
 * change it.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class Application
{
    /** @var list<string> The settings an application may set. */
    public const array SETTINGS = ['redirect_uri', 'external_sign_in', 'delivery', 'discovery', 'unlinked_handoffs', 'handoff_ttl_seconds'];

    /** @var int The handoff code's default lifetime, in seconds. */
    public const int HANDOFF_TTL_SECONDS = 60;

    /** @var int The longest a handoff code may live, in seconds. */
    public const int MAX_HANDOFF_TTL_SECONDS = 300;

    /** @var string An application's name. */
    private const string NAME = '/^[a-z][a-z0-9_\-]{0,63}$/D';

    /** @var list<string> The discovery settings. */
    private const array DISCOVERY_SETTINGS = ['enabled', 'fallback_url'];

    /**
     * Constructor.
     *
     * @param  string  $name
     * @param  string  $redirectUri
     * @param  bool  $externalSignIn
     * @param  \SineMacula\Laravel\Sso\Applications\Enums\HandoffDelivery  $delivery
     * @param  bool  $discoveryEnabled
     * @param  ?string  $discoveryFallbackUrl
     * @param  bool  $unlinkedHandoffs
     * @param  int  $handoffTtlSeconds
     */
    private function __construct(

        /** The application's name, its key under `sso.applications`. */
        public string $name,

        /** The one redirect URI, exactly as configured. */
        public string $redirectUri,

        /** Whether the configuration allows external sign-in; the policy decides. */
        public bool $externalSignIn,

        /** Where the handoff code goes on the redirect URI. */
        public HandoffDelivery $delivery,

        /** Whether the application offers discovery, while the feature is on. */
        public bool $discoveryEnabled,

        /** Where a discovery miss leads; set whenever discovery is in effect. */
        public ?string $discoveryFallbackUrl,

        /** Whether a sign-in that resolves to no identity is still handed off. */
        public bool $unlinkedHandoffs,

        /** The handoff code's lifetime, in seconds. */
        public int $handoffTtlSeconds,
    ) {}

    /**
     * Build the application from its settings, refusing unknown or malformed
     * ones without echoing their values.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $name
     * @param  mixed  $settings
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public static function fromSettings(Repository $config, string $name, mixed $settings): self
    {
        $key      = "sso.applications.{$name}";
        $settings = self::shaped($name, $key, $settings);

        $redirectUri    = UrlSetting::redirect("{$key}.redirect_uri", $settings['redirect_uri'] ?? null);
        $externalSignIn = BooleanSetting::isOn("{$key}.external_sign_in", $settings['external_sign_in'] ?? false);
        $unlinked       = BooleanSetting::isOn("{$key}.unlinked_handoffs", $settings['unlinked_handoffs'] ?? false);
        $ttl            = IntegerSetting::from("{$key}.handoff_ttl_seconds", $settings['handoff_ttl_seconds'] ?? self::HANDOFF_TTL_SECONDS, 1, self::MAX_HANDOFF_TTL_SECONDS);
        $delivery       = HandoffDelivery::tryFrom(self::stringOrEmpty($settings['delivery'] ?? HandoffDelivery::FRAGMENT->value));

        if ($delivery === null) {
            throw new \InvalidArgumentException(sprintf('`%s.delivery` must be `fragment` or `query`.', $key));
        }

        [$discovery, $fallback] = self::discovery($config, $key, $settings['discovery'] ?? []);

        return new self($name, $redirectUri, $externalSignIn, $delivery, $discovery, $fallback, $unlinked, $ttl);
    }

    /**
     * Whether the name is a valid application name.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isName(string $name): bool
    {
        return preg_match(self::NAME, $name) === 1;
    }

    /**
     * The settings, once the name is valid and no setting is unknown.
     *
     * @param  string  $name
     * @param  string  $key
     * @param  mixed  $settings
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private static function shaped(string $name, string $key, mixed $settings): array
    {
        if (!self::isName($name)) {
            $message = 'Each key of `sso.applications` must be an application name: a lower-case letter, then lower-case letters, digits, `_` and `-`,'
                . ' at most 64 in all.';

            throw new \InvalidArgumentException($message);
        }

        if (!is_array($settings)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be an array of settings.', $key));
        }

        $unknown = array_diff(array_map(strval(...), array_keys($settings)), self::SETTINGS);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('`%s` has no setting [%s]; the settings are %s.', $key, implode(', ', $unknown), implode(', ', self::SETTINGS)));
        }

        return $settings;
    }

    /**
     * Whether discovery is offered, and the fallback URL, required while the
     * feature is requested.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     * @param  string  $key
     * @param  mixed  $discovery
     * @return array{0: bool, 1: ?string}
     *
     * @throws \InvalidArgumentException
     */
    private static function discovery(Repository $config, string $key, mixed $discovery): array
    {
        if (!is_array($discovery) || array_diff(array_map(strval(...), array_keys($discovery)), self::DISCOVERY_SETTINGS) !== []) {
            throw new \InvalidArgumentException(sprintf('`%s.discovery` must be an array of `enabled` and `fallback_url`.', $key));
        }

        $offered  = BooleanSetting::isOn("{$key}.discovery.enabled", $discovery['enabled'] ?? false);
        $fallback = $discovery['fallback_url'] ?? null;

        if ($fallback === null && !($offered && Features::requested($config, Feature::DISCOVERY))) {
            return [$offered, null];
        }

        return [$offered, UrlSetting::redirect("{$key}.discovery.fallback_url", $fallback)];
    }

    /**
     * The value when it is a string, otherwise an empty string.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function stringOrEmpty(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
