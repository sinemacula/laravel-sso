<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Config\Checks;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\BooleanSetting;
use SineMacula\Laravel\Sso\Config\Enums\Feature;
use SineMacula\Laravel\Sso\Contracts\ConfigurationCheck;

/**
 * Checks the switches in `sso.features`, refusing unknown keys so a misspelt
 * switch never silently leaves a feature off.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class FeaturesCheck implements ConfigurationCheck
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
     * Always applies, since the switches decide whether anything else does.
     *
     * @return bool
     */
    #[\Override]
    public function applies(): bool
    {
        return true;
    }

    /**
     * The block's shape, then each switch with what it needs.
     *
     * @return list<\Closure(): mixed>
     */
    #[\Override]
    public function checks(): array
    {
        $checks = [
            fn (): array => $this->block(),
        ];

        foreach (Feature::cases() as $feature) {
            $checks[] = function () use ($feature): void {
                $this->feature($feature);
            };
        }

        return $checks;
    }

    /**
     * The block: an array holding no switch the package does not have.
     *
     * @return array<array-key, mixed>
     *
     * @throws \InvalidArgumentException
     */
    private function block(): array
    {
        $block = $this->config->get('sso.features', []);

        if (!is_array($block)) {
            throw new \InvalidArgumentException('`sso.features` must be an array of switches.');
        }

        $switches = array_column(Feature::cases(), 'value');
        $unknown  = array_diff(array_map(strval(...), array_keys($block)), $switches);

        if ($unknown !== []) {
            throw new \InvalidArgumentException(sprintf('`sso.features` has no switch [%s]; the switches are %s.', implode(', ', $unknown), implode(', ', $switches)));
        }

        return $block;
    }

    /**
     * The switch is a boolean and, when on, has a protocol it needs on too.
     *
     * @param  \SineMacula\Laravel\Sso\Config\Enums\Feature  $feature
     * @return void
     *
     * @throws \LogicException
     */
    private function feature(Feature $feature): void
    {
        if (!BooleanSetting::read($this->config, $feature->key(), $feature->isOnByDefault())) {
            return;
        }

        $needs = $feature->needs();

        if ($needs === []) {
            return;
        }

        foreach ($needs as $protocol) {
            if (BooleanSetting::parse($this->config->get($protocol->key(), false)) === true) {
                return;
            }
        }

        $names = implode(' or ', array_map(static fn (Feature $protocol): string => "`{$protocol->key()}`", $needs));

        throw new \LogicException(sprintf('`%s` is on, but it needs %s on as well.', $feature->key(), $names));
    }
}
