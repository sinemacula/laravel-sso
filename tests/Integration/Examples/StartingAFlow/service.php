<?php

declare(strict_types = 1);

/*
 * The service of `docs/guides/starting-a-flow.md`, resolved afresh for each
 * request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start resolve-service
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;

$requests = app(AuthorizationRequestService::class);
// @snippet-end resolve-service
return $requests;
