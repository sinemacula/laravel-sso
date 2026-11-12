<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use SineMacula\Laravel\Sso\Handoffs\Redemption\Admission;
use SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement;
use SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext;

/**
 * One purpose's rules at redemption, run under the locks inside the redeemer's
 * transaction once the common checks pass.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
interface PurposeBranch
{
    /**
     * Write nothing except a link suspension found, which is latched whatever
     * the redemption comes to.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Judgement
     */
    public function judge(RedemptionContext $context): Judgement;

    /**
     * Make the purpose's writes once `judge()` has passed.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\Redemption\RedemptionContext  $context
     * @return \SineMacula\Laravel\Sso\Handoffs\Redemption\Admission
     */
    public function admit(RedemptionContext $context): Admission;
}
