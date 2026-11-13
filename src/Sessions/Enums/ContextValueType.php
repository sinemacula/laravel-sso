<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Sessions\Enums;

/**
 * The type of a context key's value when it is not `null`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum ContextValueType: string
{
    // A string
    case STRING = 'string';

    // A list of strings
    case LIST = 'list';

    // A UTC instant in `Provenance::INSTANT_FORMAT`
    case TIME = 'time';
}
