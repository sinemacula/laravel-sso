<?php

declare(strict_types = 1);

namespace Benchmarks\Runtime;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use PhpBench\Attributes\Iterations;
use PhpBench\Attributes\Revs;
use PhpBench\Attributes\Warmup;
use SineMacula\Laravel\Sso\SsoServiceProvider;

/**
 * PHPBench suite for registering and booting the package's service provider,
 * which an application pays on every request it does not serve from a
 * long-running worker.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
#[Warmup(1)]
final readonly class ServiceProviderBench
{
    /**
     * Benchmark registering and booting the provider on a fresh application.
     *
     * @return void
     */
    #[Iterations(5)]
    #[Revs(100)]
    public function benchRegisterAndBoot(): void
    {
        $app = new Application(dirname(__DIR__, 2));
        $app->instance('config', new ConfigRepository);

        $provider = new SsoServiceProvider($app);

        $provider->register();
        $provider->boot();
    }
}
