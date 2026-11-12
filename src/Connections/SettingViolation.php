<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Connections;

use SineMacula\Laravel\Sso\Connections\Enums\ViolationCode;

/**
 * One setting a management helper refused, by dotted path and code.
 *
 * Never carries the value, so it is safe to show or log even for a secret.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SettingViolation implements \JsonSerializable
{
    /** @var int Longest setting path kept, in characters. */
    public const int MAX_SETTING_LENGTH = 255;

    /**
     * Constructor.
     *
     * @param  string  $setting
     * @param  \SineMacula\Laravel\Sso\Connections\Enums\ViolationCode  $code
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(

        /** The dotted path, such as `scopes.2` or `attribute_mapping.email`. */
        public string $setting,

        /** Why it was refused. */
        public ViolationCode $code,
    ) {
        if ($setting === '' || strlen($setting) > self::MAX_SETTING_LENGTH) {
            throw new \InvalidArgumentException(sprintf('A violation names a setting of 1 to %d bytes.', self::MAX_SETTING_LENGTH));
        }
    }

    /**
     * The setting and the code, under `setting` and `code`.
     *
     * @return array{setting: string, code: string}
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return ['setting' => $this->setting, 'code' => $this->code->value];
    }
}
