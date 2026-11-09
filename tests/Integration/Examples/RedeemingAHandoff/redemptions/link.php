<?php

declare(strict_types = 1);

/*
 * The `link` redemption of `docs/guides/redeeming-a-handoff.md` (SSO-5.11,
 * SSO-9.9, SSO-12.5), as an application's authenticated link endpoint runs it,
 * given the connection, the code and the client's verifier in `$input`, and
 * the caller the application authenticated in `$caller`, never from the body:
 * it resolves the redemption helper from the container for the request, and
 * admits the `link` code for that caller inside its own transaction on the
 * package's storage connection. It answers the redemption's result, which the
 * endpoint turns into its response after the commit.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use Tests\Integration\Examples\Clients;

/**
 * @var array{connection: string, code: string, verifier: string} $input
 * @var \SineMacula\Laravel\Sso\Identities\Caller $caller
 */
$connectionId = $input['connection'];
$code         = $input['code'];
$verifier     = $input['verifier'];

// @snippet-start redemption-helper
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;

$redemptions = app(HandoffRedemption::class);
// @snippet-end redemption-helper
// The application's own transaction, which the admitted `link` commits with
$result = null;

DB::connection(StorageConnection::name())->transaction(static function () use ($redemptions, $connectionId, $code, $verifier, $caller, &$result): void {
    $client = Clients::browser();
    // @snippet-start admit-link
    $result = $redemptions->admit(Purpose::LINK, 'web', $connectionId, $code, $verifier, $client, $caller);
    // @snippet-end admit-link
});

// Only now, after the commit, does the endpoint answer from the result
return $result;
