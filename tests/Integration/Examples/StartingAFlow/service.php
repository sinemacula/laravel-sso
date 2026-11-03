<?php

declare(strict_types = 1);

/*
 * The service of `docs/guides/starting-a-flow.md` (SSO-5.1, SSO-11.2,
 * SSO-12.5), as an application resolves it for the request it is serving: from
 * the container, afresh for each request, since a start reads the request
 * being served for the client's IP address. `StartingAFlowExampleTest` runs it
 * and starts flows through what it resolves.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

// @snippet-start resolve-service
use SineMacula\Laravel\Sso\Flows\AuthorizationRequestService;

$requests = app(AuthorizationRequestService::class);
// @snippet-end resolve-service
return $requests;
