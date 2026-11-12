<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * The endpoint a completion arrived at, with the method it takes and the flow
 * its refusals report.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CompletionEndpoint: string
{
    // The SAML assertion consumer service, which accepts HTTP-POST only
    case ASSERTION_CONSUMER_SERVICE = 'assertion_consumer_service';

    // The OIDC callback, which accepts the authorisation response's GET
    case CALLBACK = 'callback';

    /**
     * The flow a refusal at the endpoint reports.
     *
     * @return \SineMacula\Laravel\Sso\Events\Enums\Flow
     */
    public function flow(): Flow
    {
        return match ($this) {
            self::ASSERTION_CONSUMER_SERVICE => Flow::ASSERTION,
            self::CALLBACK                   => Flow::CALLBACK,
        };
    }

    /**
     * The HTTP method the endpoint takes, in upper case.
     *
     * @return string
     */
    public function method(): string
    {
        return match ($this) {
            self::ASSERTION_CONSUMER_SERVICE => 'POST',
            self::CALLBACK                   => 'GET',
        };
    }
}
