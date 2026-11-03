<?php

declare(strict_types = 1);

/*
 * The invitation acceptance of `docs/guides/single-use-store.md` (SSO-11.5,
 * SSO-12.5), as the application's own route does it, given the token presented
 * and the application's invitations: an invitation unknown or closed is not
 * found, and an open one is accepted once, by recording its token in a
 * namespace of the application's own in the package's single-use store until
 * the invitation closes; presented again, it is refused as used.
 * `SingleUseStoreExampleTest` runs it and asserts each answer.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */

namespace Tests\Integration\Examples\SingleUseStore;

/** @var array{token: string, invitations: \Tests\Integration\Examples\SingleUseStore\Invitations} $input */
$token     = $input['token'];
$expiresAt = $input['invitations']->openUntil($token);

if ($expiresAt === null) {
    return response()->json(['error' => 'invitation_not_found'], 404);
}

// @snippet-start record-once
use SineMacula\Laravel\Sso\Contracts\SingleUseStore;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

$outcome = app(SingleUseStore::class)->record('invitation', $token, $expiresAt);

if ($outcome !== SingleUseOutcome::RECORDED) {
    // `seen`: already accepted, so refuse it
    return response()->json(['error' => 'invitation_used'], 409);
}
// @snippet-end record-once
return response()->json(['accepted' => true]);
