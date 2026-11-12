<?php

declare(strict_types = 1);

/*
 * The invitation acceptance route of `docs/guides/single-use-store.md`.
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
