<?php

declare(strict_types = 1);

/*
 * The adapter's `sign_in` redemption, as its endpoint runs it with `$input`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\IntegratingWithLaravelIam;

use Tests\Integration\Examples\Clients;

/** @var array{application: string, connection: string, code: string, verifier: string} $input */
$application  = $input['application'];
$connectionId = $input['connection'];
$code         = $input['code'];
$verifier     = $input['verifier'];

$client = Clients::browser();
// @snippet-start iam-sign-in
use Illuminate\Support\Facades\DB;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Handoffs\HandoffRedemption;
use SineMacula\Laravel\Sso\Handoffs\RedemptionResult;

$storage = DB::connection(StorageConnection::name());

$answer = $storage->transaction(static function () use ($application, $connectionId, $code, $verifier, $client): RedemptionResult|SignInResult {
    $redemption = app(HandoffRedemption::class)
        ->admit(Purpose::SIGN_IN, $application, $connectionId, $code, $verifier, $client);

    if (!$redemption->isRedeemed()) {
        return $redemption; // a refusal commits: the code is spent and one FlowFailed follows
    }

    if ($redemption->linkedIdentity === null) {
        throw new UnlinkedSignIn; // the adapter always requires a linked identity: roll back
    }

    app(AdmittedRedemptions::class)->record($redemption); // request scoped, for the link contract

    $signIn = Auth::sessions()->signInExternally(ExternalResults::from($redemption)); // PR #127

    if ($signIn->isFailed()) {
        throw new ExternalSignInRefused($signIn); // roll back: the code stays unspent
    }

    return $signIn; // signed in or pending
});

// Only now, after the commit, build the response from $answer, with
// Cache-Control: no-store.
// @snippet-end iam-sign-in
return $answer;
