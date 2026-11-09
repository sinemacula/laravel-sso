<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\LinkingByDomain;

use Illuminate\Validation\ValidationException;
use SineMacula\Laravel\Sso\Connections\ConnectionResult;
use SineMacula\Laravel\Sso\Connections\LinkingPolicyService;
use SineMacula\Laravel\Sso\Identities\Caller;
use Tests\Integration\Examples\Clients;

/**
 * The example application's administration action that turns linking by a
 * verified domain on for a tenant's connection (SSO-8.8, SSO-2.12): the issuer
 * is classified as shared, its organisations told apart by the `hd` claim, and
 * the administrator gives the value their organisation holds there. Settings
 * the package finds invalid are answered as the application's validation
 * errors, each naming the setting and the code, never the value given.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkingSettings
{
    /**
     * Turn the connection's linking on, as the administrator.
     *
     * @param  string  $tenantId
     * @param  string  $connectionId
     * @param  ?string  $organization
     * @param  \SineMacula\Laravel\Sso\Identities\Caller  $caller
     * @return \SineMacula\Laravel\Sso\Connections\ConnectionResult
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function enable(string $tenantId, string $connectionId, ?string $organization, Caller $caller): ConnectionResult
    {
        $client = Clients::browser();
        // @snippet-start linking-policy-change
        $result = app(LinkingPolicyService::class)->change($tenantId, $connectionId, [
            'enabled'            => true,
            'issuer_class'       => 'shared', // or single_organization, acknowledged
            'organization_claim' => 'hd',
            'organization_value' => $organization,
        ], $client, $caller);

        if ($result->isInvalid()) {
            // Each violation names a setting and a code, never the value given
            $messages = [];

            foreach ($result->violations as $violation) {
                $messages[$violation->setting][] = $violation->code->value;
            }

            throw ValidationException::withMessages($messages);
        }
        // @snippet-end linking-policy-change
        return $result;
    }
}
