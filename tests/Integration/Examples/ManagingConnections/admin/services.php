<?php

declare(strict_types = 1);

/*
 * The services of `docs/guides/managing-connections.md` (SSO-2.11, SSO-2.13,
 * SSO-12.5), resolved from the container as the application's administration
 * endpoints resolve them for each request: the service that creates, changes,
 * reads and enables a tenant's connections, the lifecycle that disables and
 * deletes them, and the migration that moves their links to a new subject. It
 * answers the three, in that order.
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
