<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Config\UrlSetting;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * `[endpoints]`: what the default endpoint resolver builds the package's URLs
 * from (SSO-5.5), while the package is in use, so a resolver that cannot build
 * them fails at boot rather than on the first sign-in (SSO-12.3).
 *
 * `sso.endpoints.base_url` is a web URL with no query (see
 * `UrlSetting::web()`), and each pattern in `sso.endpoints.paths` an absolute
 * path holding `{connection}` once, with no query, fragment, wildcard or dot
 * segment, and distinct from the others. Nothing is ever built from the
 * request's host or headers. An application that binds a resolver of its own
 * still names these, since the default's settings are what this checks.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class EndpointsCheck implements ConfigurationCheck
{
    /** @var list<string> The endpoints whose path patterns are configured. */
    public const array PATHS = ['assertion_consumer_service', 'callback', 'metadata'];

    /** @var string A path pattern: an absolute path of unreserved characters, `/`, `{` and `}`. */
    private const string PATTERN = '#^/[A-Za-z0-9\-._~/{}]*$#';

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
     * The endpoints are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * The base URL, each path pattern, then that the patterns are distinct.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [
            fn (): string => UrlSetting::web('sso.endpoints.base_url', $this->config->get('sso.endpoints.base_url'), query: false),
        ];

        foreach (self::PATHS as $endpoint) {
            $checks[] = fn (): string => $this->path($endpoint);
        }

        $checks[] = function (): void {
            $this->distinct();
        };

        return $checks;
    }

    /**
     * The endpoint's path pattern.
     *
     * @param  string  $endpoint
     * @return string
     *
     * @throws \InvalidArgumentException
     */
    private function path(string $endpoint): string
    {
        $key     = "sso.endpoints.paths.{$endpoint}";
        $pattern = $this->config->get($key);

        if (!is_string($pattern) || !self::isPattern($pattern)) {
            $message = '`%s` must be an absolute path holding `{connection}` once, with no query, fragment, other placeholder or dot segment.';

            throw new \InvalidArgumentException(sprintf($message, $key));
        }

        return $pattern;
    }

    /**
     * Whether the pattern is an absolute path of allowed characters, holding
     * `{connection}` once, no other brace, and no dot segment.
     *
     * @param  string  $pattern
     * @return bool
     */
    private static function isPattern(string $pattern): bool
    {
        return preg_match(self::PATTERN, $pattern)                             === 1
            && substr_count($pattern, '{connection}')                          === 1
            && preg_match('#[{}]#', str_replace('{connection}', '', $pattern)) === 0
            && preg_match('#(^|/)\.{1,2}(/|$)#', $pattern)                     === 0;
    }

    /**
     * Refuse two endpoints with the same pattern; patterns the other checks
     * refuse are left to them.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function distinct(): void
    {
        $seen = [];

        foreach (self::PATHS as $endpoint) {

            $pattern = $this->config->get("sso.endpoints.paths.{$endpoint}");

            if (!is_string($pattern)) {
                continue;
            }

            if (isset($seen[$pattern])) {
                throw new \InvalidArgumentException(sprintf('`sso.endpoints.paths.%s` and `sso.endpoints.paths.%s` must differ.', $seen[$pattern], $endpoint));
            }

            $seen[$pattern] = $endpoint;
        }
    }
}
