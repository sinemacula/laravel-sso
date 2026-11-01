<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\BooleanSetting;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Config\IntegerSetting;
use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[applications]`: the applications in `sso.applications`, while the package
 * is in use, each named by a lower-case key.
 *
 * An application has exactly one redirect URI, compared later as an exact
 * string (see `UrlSetting::redirect()`), and may set whether it allows sign-in
 * through an external provider (off unless set), whether the handoff code is
 * delivered in the fragment (the default) or the query, whether it offers
 * discovery and the fallback URL a miss leads to (required while discovery is
 * on for it and the `discovery` feature is on), whether it accepts unlinked
 * handoffs (off unless set), and the handoff code's lifetime (1 to 300 seconds,
 * 60 by default). Any other key is refused, so a misspelt setting is never
 * silently left at its default.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ApplicationsCheck implements ConfigurationCheck
{
    /** @var list<string> The settings an application may set. */
    public const array SETTINGS = ['redirect_uri', 'external_sign_in', 'delivery', 'discovery', 'unlinked_handoffs', 'handoff_ttl_seconds'];

    /** @var list<string> Where a handoff code may be delivered on the redirect URI. */
    public const array DELIVERIES = ['fragment', 'query'];

    /** @var int The handoff code's default lifetime, in seconds (SSO-9.2). */
    public const int HANDOFF_TTL_SECONDS = 60;

    /** @var int The longest a handoff code may live, in seconds (SSO-9.2). */
    public const int MAX_HANDOFF_TTL_SECONDS = 300;

    /** @var string An application's name. */
    private const string NAME = '/^[a-z][a-z0-9_\-]{0,63}$/';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration checked. */
        private Repository $config,
    ) {}

    /**
     * The applications are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The block's shape, then each application.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $applications = $this->config->get('sso.applications', []);

        if (!is_array($applications)) {
            return [
                static function (): void {
                    throw new \InvalidArgumentException('`sso.applications` must be an array of applications, by name.');
                },
            ];
        }

        $checks = [];

        foreach ($applications as $name => $settings) {
            $checks[] = function () use ($name, $settings): void {
                $this->application((string) $name, $settings);
            };
        }

        return $checks;
    }

    /**
     * One application's name and settings.
     *
     * @param  string  $name
     * @param  mixed  $settings
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function application(string $name, mixed $settings): void
    {
        $key      = "sso.applications.{$name}";
        $settings = self::shaped($name, $key, $settings);

        UrlSetting::redirect("{$key}.redirect_uri", $settings['redirect_uri'] ?? null);
        BooleanSetting::isOn("{$key}.external_sign_in", $settings['external_sign_in'] ?? false);
        BooleanSetting::isOn("{$key}.unlinked_handoffs", $settings['unlinked_handoffs'] ?? false);
        IntegerSetting::from("{$key}.handoff_ttl_seconds", $settings['handoff_ttl_seconds'] ?? self::HANDOFF_TTL_SECONDS, 1, self::MAX_HANDOFF_TTL_SECONDS);

        if (!in_array($settings['delivery'] ?? 'fragment', self::DELIVERIES, true)) {
            throw new \InvalidArgumentException(sprintf('`%s.delivery` must be `fragment` or `query`.', $key));
        }

        $this->discovery($key, $settings['discovery'] ?? []);
    }

    /**
     * One application's settings, once its name is a name and they are an array
     * holding no setting the package does not have.
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
        if (preg_match(self::NAME, $name) !== 1) {
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
     * One application's discovery settings: whether it offers discovery, and
     * the fallback URL a miss leads to, required while it does and the
     * `discovery` feature is on.
     *
     * @param  string  $key
     * @param  mixed  $discovery
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function discovery(string $key, mixed $discovery): void
    {
        if (!is_array($discovery) || array_diff(array_map(strval(...), array_keys($discovery)), ['enabled', 'fallback_url']) !== []) {
            throw new \InvalidArgumentException(sprintf('`%s.discovery` must be an array of `enabled` and `fallback_url`.', $key));
        }

        $offered  = BooleanSetting::isOn("{$key}.discovery.enabled", $discovery['enabled'] ?? false);
        $fallback = $discovery['fallback_url'] ?? null;

        if ($fallback === null && !($offered && Features::requested(Feature::DISCOVERY))) {
            return;
        }

        UrlSetting::redirect("{$key}.discovery.fallback_url", $fallback);
    }
}
