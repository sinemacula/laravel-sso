<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use SineMacula\Laravel\Sso\Connections\ConnectionLifecycle;
use SineMacula\Laravel\Sso\Connections\ConnectionService;
use SineMacula\Laravel\Sso\Http\ClientContext;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\Routes\Application\Answers;
use Tests\Integration\Examples\Routes\Application\Caller;

/**
 * The example application's connection management routes, each scoped to the
 * caller's active tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoConnectionController
{
    /**
     * Manage connections through the package's helpers.
     *
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionService  $connections
     * @param  \SineMacula\Laravel\Sso\Connections\ConnectionLifecycle  $lifecycle
     */
    public function __construct(

        /** Creates, reads, changes and enables connections. */
        private ConnectionService $connections,

        /** Disables and deletes connections. */
        private ConnectionLifecycle $lifecycle,
    ) {}

    /**
     * `GET /auth/sso/connections`: the tenant's connections.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function index(Request $request): JsonResponse
    {
        return response()->json($this->connections->list(Caller::tenantId($request)), 200, Answers::NO_STORE);
    }

    /**
     * `POST /auth/sso/connections`: create one, disabled.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): JsonResponse
    {
        // @snippet-start route-connection-create
        /** @var array{protocol: string, display_name: string, settings?: array<string, mixed>, attribute_mapping?: array<string, string>, preset?: ?string} $input */
        $input = Validator::validate($request->all(), [
            'protocol'          => ['required', 'string'],
            'display_name'      => ['required', 'string'],
            'settings'          => ['array'],
            'attribute_mapping' => ['array'],
            'preset'            => ['nullable', 'string'],
        ]);

        // The tenant is the caller's active one, never the body's
        $result = $this->connections->create(
            tenantId: Caller::tenantId($request),
            protocol: $input['protocol'],
            displayName: $input['display_name'],
            client: ClientContext::fromRequest($request),
            settings: $input['settings']                  ?? [],
            attributeMapping: $input['attribute_mapping'] ?? [],
            preset: $input['preset']                      ?? null,
            caller: Caller::of($request),
        );

        return Answers::of($result, 201);
        // @snippet-end route-connection-create
    }

    /**
     * `GET /auth/sso/connections/{connection}`: one of the tenant's.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function show(Request $request, string $connection): JsonResponse
    {
        // @snippet-start route-connection-show
        $summary = $this->connections->get(Caller::tenantId($request), $connection);

        if ($summary === null) {
            abort(404); // unknown, or another tenant's: the same answer
        }

        return response()->json($summary, 200, Answers::NO_STORE);
        // @snippet-end route-connection-show
    }

    /**
     * `PATCH /auth/sso/connections/{connection}`: change its settings, its
     * mapping or its name.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function update(Request $request, string $connection): JsonResponse
    {
        /** @var array<string, mixed> $changes */
        $changes = $request->only(['display_name', 'settings', 'attribute_mapping']);

        return Answers::of($this->connections->update(Caller::tenantId($request), $connection, $changes, Clients::browser(), Caller::of($request)));
    }

    /**
     * `POST /auth/sso/connections/{connection}/enable`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function enable(Request $request, string $connection): JsonResponse
    {
        return Answers::of($this->connections->enable(Caller::tenantId($request), $connection, Clients::browser(), Caller::of($request)));
    }

    /**
     * `POST /auth/sso/connections/{connection}/disable`: its sessions are
     * revoked through the application's `SessionRevocation`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function disable(Request $request, string $connection): JsonResponse
    {
        return Answers::of($this->lifecycle->disable(Caller::tenantId($request), $connection, Clients::browser(), Caller::of($request)));
    }

    /**
     * `DELETE /auth/sso/connections/{connection}`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function destroy(Request $request, string $connection): JsonResponse
    {
        return Answers::of($this->lifecycle->delete(Caller::tenantId($request), $connection, Clients::browser(), Caller::of($request)));
    }
}
