<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Routes\Controllers;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use SineMacula\Laravel\Sso\Domains\DomainService;
use SineMacula\Laravel\Sso\Http\ClientContext;
use Tests\Integration\Examples\Clients;
use Tests\Integration\Examples\Routes\Application\Answers;
use Tests\Integration\Examples\Routes\Application\Caller;

/**
 * The example application's domain routes, scoped to the caller's tenant.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class SsoDomainController
{
    /**
     * Manage domains through the package's helper.
     *
     * @param  \SineMacula\Laravel\Sso\Domains\DomainService  $domains
     */
    public function __construct(

        /** Claims, verifies and removes domains. */
        private DomainService $domains,
    ) {}

    /**
     * `POST /auth/sso/connections/{connection}/domains`: claim one, and show
     * the record to publish.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request, string $connection): JsonResponse
    {
        // @snippet-start route-domain-claim
        /** @var array{domain: string} $input */
        $input  = Validator::validate($request->all(), ['domain' => ['required', 'string', 'max:253']]);
        $result = $this->domains->claim(Caller::tenantId($request), $connection, $input['domain'], ClientContext::fromRequest($request), Caller::of($request));

        // The token is shown to the administrator to publish, and never logged
        $record = $result->domain === null ? null : ['name' => $result->domain->recordName, 'value' => $result->domain->verificationToken()];

        return Answers::of($result, 201, ['domain' => $result->domain, 'record' => $record]);
        // @snippet-end route-domain-claim
    }

    /**
     * `POST /auth/sso/connections/{connection}/domains/{domain}/verifications`:
     * look the record up.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @param  string  $domain
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function verify(Request $request, string $connection, string $domain): JsonResponse
    {
        return Answers::of($this->domains->verify(Caller::tenantId($request), $connection, $domain, Clients::browser(), Caller::of($request)));
    }

    /**
     * `DELETE /auth/sso/connections/{connection}/domains/{domain}`.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  string  $connection
     * @param  string  $domain
     * @return \Illuminate\Http\JsonResponse
     *
     * @throws \Illuminate\Auth\AuthenticationException
     */
    public function destroy(Request $request, string $connection, string $domain): JsonResponse
    {
        return Answers::of($this->domains->remove(Caller::tenantId($request), $connection, $domain, Clients::browser(), Caller::of($request)));
    }
}
