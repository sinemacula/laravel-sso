<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples;

/**
 * Autoloads the examples' stand-ins for the sibling packages' APIs under the
 * siblings' own names, so guide code that names them runs as written.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SiblingStandIns
{
    /** @var array<string, string> The directory of each sibling's stand-ins, by its namespace. */
    private const array DIRECTORIES = [
        'SineMacula\Laravel\AuditLog\\'       => __DIR__ . '/Events/AuditLog/',
        'SineMacula\Laravel\Authentication\\' => __DIR__ . '/IntegratingWithLaravelIam/Authentication/',
    ];

    /** @var bool Whether the autoloader is registered. */
    private static bool $registered = false;

    /**
     * Register the autoloader of the stand-ins, once.
     *
     * @return void
     */
    public static function register(): void
    {
        if (self::$registered) {
            return;
        }

        spl_autoload_register(self::load(...));

        self::$registered = true;
    }

    /**
     * Load the stand-in of the class, if it is one.
     *
     * @param  string  $class
     * @return void
     */
    private static function load(string $class): void
    {
        foreach (self::DIRECTORIES as $namespace => $directory) {

            $file = $directory . str_replace('\\', '/', substr($class, strlen($namespace))) . '.php';

            if (str_starts_with($class, $namespace) && is_file($file)) {
                require_once $file;

                return;
            }
        }
    }
}
