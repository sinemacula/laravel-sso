<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Exceptions\MissingExtensionException;

/**
 * `[extensions]`: the PHP extensions and functions the package needs, while it
 * is in use. Composer requires them, but an install that ignored the platform,
 * or a runtime built without one, would otherwise fail on the first request
 * that reached for it; this names the missing one at boot instead.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class ExtensionsCheck implements ConfigurationCheck
{
    /** @var array<string, string> Each extension the package needs, and what for. */
    public const array EXTENSIONS = [
        'curl'     => 'the outbound fetcher, which pins the address it checked with CURLOPT_RESOLVE',
        'dom'      => 'parsing SAML messages and metadata',
        'hash'     => 'digests and constant-time comparison',
        'libxml'   => 'parsing SAML messages and metadata',
        'mbstring' => 'length caps and sanitising of multibyte text',
        'openssl'  => 'keys, certificates, signatures and encryption',
        'zlib'     => 'the DEFLATE encoding of the SAML HTTP-Redirect binding',
    ];

    /** @var \Closure(string): bool Whether an extension is loaded. */
    private \Closure $loaded;

    /** @var \Closure(string): bool Whether a function exists. */
    private \Closure $exists;

    /**
     * Constructor.
     *
     * @param  ?\Closure(string): bool  $loaded
     * @param  ?\Closure(string): bool  $exists
     */
    public function __construct(?\Closure $loaded = null, ?\Closure $exists = null)
    {
        $this->loaded = $loaded ?? extension_loaded(...);
        $this->exists = $exists ?? function_exists(...);
    }

    /**
     * The extensions are checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse();
    }

    /**
     * One check per extension, then the IDNA conversion domains are normalised
     * with (SSO-3.1), from `ext-intl` or `symfony/polyfill-intl-idn`.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [];

        foreach (self::EXTENSIONS as $extension => $purpose) {
            $checks[] = function () use ($extension, $purpose): void {
                if (!($this->loaded)($extension)) {
                    throw new MissingExtensionException(sprintf('The PHP extension `%s` is not loaded; laravel-sso needs it for %s.', $extension, $purpose));
                }
            };
        }

        $checks[] = function (): void {
            if (!($this->exists)('idn_to_ascii')) {
                $message = '`idn_to_ascii()` is not available; laravel-sso needs it, from `ext-intl` or `symfony/polyfill-intl-idn`, to normalise domains.';

                throw new MissingExtensionException($message);
            }
        };

        return $checks;
    }
}
