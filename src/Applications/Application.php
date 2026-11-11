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
 * One application people sign into through a connection (SSO-5.5, decision D7),
 * as `sso.applications.<name>` registers it: the suite's own front ends, a
 * fixed set deployed with the code.
 *
 * It has exactly one redirect URI, used exactly as configured: never chosen,
 * extended or altered by anything in a request, and there is no return URL. It
 * says whether it allows sign-in through an external provider (off unless set),
 * where a handoff code is delivered on the redirect URI, whether it offers
 * discovery and the fallback URL a miss leads to, whether a sign-in that
 * resolves to no identity is still handed off, and how long a handoff code
 * lives.
 *
 * Built only by `fromSettings()`, which judges a configuration the one way both
 * the boot check (`Config\Checks\ApplicationsCheck`) and the flows judge it,
 * failing closed with an `InvalidArgumentException` that names the key and what
 * it must be, never the configured value. Any setting the package does not have
 * is refused, so a misspelt one is never silently left at its default.
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

    /** @var int The handoff code's default lifetime, in seconds (SSO-9.2). */
    public const int HANDOFF_TTL_SECONDS = 60;

    /** @var int The longest a handoff code may live, in seconds (SSO-9.2). */
    public const int MAX_HANDOFF_TTL_SECONDS = 300;

    /** @var string An application's name: a lower-case letter, then up to 63 lower-case letters, digits, `_` and `-`, with nothing after them. */
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

        /** The one redirect URI configured, exactly as configured. */
        public string $redirectUri,

        /** Whether the configuration allows sign-in through an external provider; the application policy decides. */
        public bool $externalSignIn,

        /** Where the handoff code goes on the redirect URI. */
        public HandoffDelivery $delivery,

        /** Whether the application offers discovery, while the `discovery` feature is on. */
        public bool $discoveryEnabled,

        /** Where a discovery miss leads; set whenever discovery is offered with the feature on. */
        public ?string $discoveryFallbackUrl,

        /** Whether a sign-in that resolves to no identity is still handed off. */
        public bool $unlinkedHandoffs,

        /** The handoff code's lifetime, in seconds. */
        public int $handoffTtlSeconds,
    ) {}

    /**
     * The application the settings under the name describe, judged against the
     * features the repository switches on.
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
     * Whether the name is an application's name: a lower-case letter, then up
     * to 63 lower-case letters, digits, `_` and `-`.
     *
     * @param  string  $name
     * @return bool
     */
    public static function isName(string $name): bool
    {
        return preg_match(self::NAME, $name) === 1;
    }

    /**
     * The settings, once the name is a name and they are an array holding no
     * setting the package does not have.
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
     * Whether the application offers discovery, and the fallback URL a miss
     * leads to: required while it offers discovery and the `discovery` feature
     * is on (or its switch is malformed), and checked whenever it is given.
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
     * The value when it is a string, and an empty string otherwise, which no
     * delivery is.
     *
     * @param  mixed  $value
     * @return string
     */
    private static function stringOrEmpty(mixed $value): string
    {
        return is_string($value) ? $value : '';
    }
}
