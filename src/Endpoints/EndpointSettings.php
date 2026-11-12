<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Endpoints;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint;

/**
 * The `sso.endpoints` settings, read the same way by the resolver and the boot
 * check.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class EndpointSettings
{
    /** @var string The placeholder each pattern holds once, for the connection's id. */
    public const string PLACEHOLDER = '{connection}';

    /** @var string An absolute path of unreserved characters and braces. */
    private const string PATTERN = '#^/[A-Za-z0-9\-._~/{}]*$#D';

    /** @var string A dot segment anywhere in a path. */
    private const string DOT_SEGMENT = '#(^|/)\.{1,2}(/|$)#';

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration the settings are read from. */
        private Repository $config,
    ) {}

    /**
     * The base URL every endpoint is built on.
     *
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function baseUrl(): string
    {
        return UrlSetting::web('sso.endpoints.base_url', $this->config->get('sso.endpoints.base_url'), query: false);
    }

    /**
     * The endpoint's path pattern.
     *
     * @param  \SineMacula\Laravel\Sso\Endpoints\Enums\Endpoint  $endpoint
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    public function pattern(Endpoint $endpoint): string
    {
        $key     = "sso.endpoints.paths.{$endpoint->value}";
        $pattern = $this->config->get($key);

        if (!is_string($pattern) || !self::isPattern($pattern)) {
            $message = '`%s` must be an absolute path holding `{connection}` once, with no query, fragment, other placeholder or dot segment.';

            throw new \InvalidArgumentException(sprintf($message, $key));
        }

        return $pattern;
    }

    /**
     * Refuse two endpoints with the same pattern.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    public function assertDistinct(): void
    {
        $seen = [];

        foreach (Endpoint::cases() as $endpoint) {

            $pattern = $this->config->get("sso.endpoints.paths.{$endpoint->value}");

            if (!is_string($pattern)) {
                continue;
            }

            if (isset($seen[$pattern])) {
                throw new \InvalidArgumentException(sprintf('`sso.endpoints.paths.%s` and `sso.endpoints.paths.%s` must differ.', $seen[$pattern], $endpoint->value));
            }

            $seen[$pattern] = $endpoint->value;
        }
    }

    /**
     * Whether the pattern holds `{connection}` once, no other brace and no dot
     * segment.
     *
     * @param  string  $pattern
     * @return bool
     */
    private static function isPattern(string $pattern): bool
    {
        return preg_match(self::PATTERN, $pattern)                                === 1
            && substr_count($pattern, self::PLACEHOLDER)                          === 1
            && preg_match('#[{}]#', str_replace(self::PLACEHOLDER, '', $pattern)) === 0
            && preg_match(self::DOT_SEGMENT, $pattern)                            === 0;
    }
}
