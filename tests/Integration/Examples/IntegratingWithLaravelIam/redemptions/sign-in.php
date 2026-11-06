<?php

declare(strict_types = 1);

/*
 * The adapter's `sign_in` redemption of
 * `docs/guides/integrating-with-laravel-iam.md` (SSO-9.2, SSO-9.9, SSO-12.5),
 * as its redemption endpoint runs it, given the application, the connection,
 * the code and the client's verifier: the package admits the code first, then
 * authentication's external sign-in establishes the session, in that one
 * transaction on the package's storage connection. A refusal by the package
 * commits; one by authentication, or an unlinked result, rolls back. It answers
 * the refusal or the sign-in, which the endpoint turns into its response only
 * after the commit.
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
