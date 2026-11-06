<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Enums;

use SineMacula\Laravel\Sso\Events\Enums\Flow;

/**
 * The endpoint a completion arrived at (SSO-5.3, SSO-5.4, SSO-5.5): a
 * connection's SAML assertion consumer service or its OIDC callback, the two
 * the identity provider sends the browser back to. The application's route for
 * each names its endpoint when it calls `Completion\CompletionService`.
 *
 * Each endpoint takes one HTTP method, and its refusals report one flow: the
 * assertion consumer service takes `POST` (the HTTP-POST binding) and reports
 * `Flow::ASSERTION`; the callback takes `GET` and reports `Flow::CALLBACK`. The
 * values are those of the matching cases of `Endpoints\Enums\Endpoint`, whose
 * paths the endpoint resolver builds.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum CompletionEndpoint: string
{
    // The SAML assertion consumer service, which accepts HTTP-POST only
    // (SSO-5.3)
    case ASSERTION_CONSUMER_SERVICE = 'assertion_consumer_service';

    // The OIDC callback, which accepts the authorisation response's GET
    // (SSO-5.4)
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
