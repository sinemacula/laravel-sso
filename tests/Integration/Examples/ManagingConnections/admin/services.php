<?php

declare(strict_types = 1);

/*
 * The services of `docs/guides/managing-connections.md`, resolved per request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\ManagingConnections;

// @snippet-start connections-services
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Connections\SubjectMigration;

$connections = app(ConnectionService::class);
$lifecycle   = app(ConnectionLifecycle::class);
$migration   = app(SubjectMigration::class);
// @snippet-end connections-services
return [$connections, $lifecycle, $migration];
