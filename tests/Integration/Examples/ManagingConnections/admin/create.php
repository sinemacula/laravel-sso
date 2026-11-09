<?php

declare(strict_types = 1);

/*
 * The create endpoint of `docs/guides/managing-connections.md` (SSO-2.11,
 * SSO-2.12, SSO-12.5), as the application's administration screen runs it once
 * its own authorisation has let the signed-in user manage the tenant's
 * connections, given the connection service, the tenant, that user and the
 * request: the package creates a disabled Google Workspace connection from the
 * `google` preset and the client the form names, for the user on their session
 * as the caller: freshness judges that caller, and the event it reports names
 * the user as the acting identity. An invalid form goes back with each
 * violation under the setting it names; any other result is answered for the
 * endpoint to turn into its response.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\ManagingConnections;

/**
 * @var array{
 *     connections: \SineMacula\Laravel\Sso\Connections\ConnectionService,
 *     tenant: \Tests\Integration\Examples\ManagingConnections\Tenant,
 *     user: \Tests\Integration\Examples\ManagingConnections\User,
 *     request: \Illuminate\Http\Request,
 * } $input
 */
$connections = $input['connections'];
$tenant      = $input['tenant'];
$user        = $input['user'];
$request     = $input['request'];

// @snippet-start connections-create
use SineMacula\Laravel\Sso\Connections\SettingViolation;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\Caller;
use SineMacula\Laravel\Sso\Identities\IdentityReference;

$result = $connections->create(
    tenantId: $tenant->id,
    protocol: 'oidc',
    displayName: 'Acme Google Workspace',
    client: ClientContext::fromRequest($request),
    settings: [
        'client_id'     => '1234.apps.googleusercontent.com',
        'client_secret' => $request->input('client_secret'),
    ],
    preset: 'google',
    caller: new Caller(new IdentityReference($user->getMorphClass(), (string) $user->getKey()), $request->session()->getId()),
);

if ($result->isInvalid()) {
    $errors = collect($result->violations)->mapWithKeys(fn (SettingViolation $violation): array => [$violation->setting => $violation->code->value]);

    return back()->withErrors($errors->all());
}
// @snippet-end connections-create
return $result;
