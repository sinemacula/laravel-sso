<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;

/**
 * One purpose's rules at redemption (SSO-9.9, `docs/design/linking.md`), once
 * the code is consumed and the checks common to every purpose have passed,
 * under the locks, inside the redeemer's transaction. `judge()` writes nothing
 * except a link
 * suspension it finds, which is latched whatever the redemption comes to; `admit()`
 * makes the purpose's writes after it passed.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PurposeBranch
{
    /**
     * Whether the purpose's rules let the redemption go on.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Enums\RecheckOutcome
     */
    public function judge(RedemptionContext $context): RecheckOutcome;

    /**
     * Make the purpose's writes, once its rules passed.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    public function admit(RedemptionContext $context): Admission;
}
