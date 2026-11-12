<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A SAML document the adapter refused; never thrown past the adapter. Its
 * message is the rule's name and it keeps no previous exception, so it never
 * quotes the document.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class ReadFailure extends \RuntimeException
{
    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Sso\Events\Enums\FailureReason  $reason
     * @param  string  $detail
     */
    public function __construct(

        /** Why the document was refused. */
        public readonly FailureReason $reason,

        /** Which rule refused it, in the package's own words. */
        public readonly string $detail,
    ) {
        parent::__construct($detail);
    }
}
