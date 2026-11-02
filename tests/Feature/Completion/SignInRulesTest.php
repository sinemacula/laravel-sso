<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Rules\SignInRules;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use Tests\TestCase;

/**
 * Feature tests for the rules of a `sign_in` (SSO-8.8): a suspended link and a
 * live reservation each refuse it for its own reason; anything else, including
 * a link not yet resolved, goes on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SignInRules::class)]
final class SignInRulesTest extends TestCase
{
    /**
     * A suspended link is refused as suspended, and a live reservation as
     * reserved.
     *
     * @return void
     */
    public function testWhatHoldsTheSubjectRefuses(): void
    {
        $holder = new IdentityReference('user', '1');

        self::assertSame(FailureReason::LINK_SUSPENDED, (new SignInRules)->refusal(self::state()->withResolution(LinkResolution::suspended($holder, 'link-1'))));
        self::assertSame(FailureReason::LINK_RESERVED, (new SignInRules)->refusal(self::state()->withResolution(LinkResolution::reserved())));
    }

    /**
     * A link not yet resolved, an absent one and an active one go on.
     *
     * @return void
     */
    public function testAnythingElseGoesOn(): void
    {
        self::assertNull((new SignInRules)->refusal(self::state()));
        self::assertNull((new SignInRules)->refusal(self::state()->withResolution(LinkResolution::absent())));
        self::assertNull((new SignInRules)->refusal(self::state()->withResolution(LinkResolution::linked(new IdentityReference('user', '1'), 'link-1'))));
    }

    /**
     * A state that has only arrived.
     *
     * @return \SineMacula\Laravel\Sso\Completion\CompletionState
     */
    private static function state(): CompletionState
    {
        return CompletionState::arrived('01jbexampleconnection00000', new CompletionRequest('GET', '', []));
    }
}
