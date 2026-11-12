<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Freshness;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\Features;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;
use SineMacula\Laravel\Sso\Freshness\Enums\FreshnessOperation;

/**
 * `[freshness]`: checks each operation's maximum age and refuses unknown
 * operation keys.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FreshnessCheck implements ConfigurationCheck
{
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
     * Freshness is checked while the package is in use.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return Features::isInUse($this->config);
    }

    /**
     * The block's shape, then each operation's maximum age.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $ages   = new MaximumAges($this->config);
        $checks = [
            function (): void {
                $this->block();
            },
        ];

        foreach (FreshnessOperation::cases() as $operation) {
            $checks[] = static fn (): int => $ages->for($operation);
        }

        return $checks;
    }

    /**
     * Check the block is an array keyed by operations only, so a misspelt key
     * fails.
     *
     * @return void
     *
     * @throws \InvalidArgumentException
     */
    private function block(): void
    {
        $block = $this->config->get(MaximumAges::BLOCK, []);

        if (!is_array($block)) {
            throw new \InvalidArgumentException(sprintf('`%s` must be an array of maximum ages by operation.', MaximumAges::BLOCK));
        }

        $known   = array_map(static fn (FreshnessOperation $operation): string => $operation->configKey(), FreshnessOperation::cases());
        $unknown = array_diff(array_map(strval(...), array_keys($block)), $known);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('`%s` has no operation [%s]; the operations are %s.', MaximumAges::BLOCK, implode(', ', $unknown), implode(', ', $known)));
        }
    }
}
