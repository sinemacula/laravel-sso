<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Saml2\Library;

use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * A SAML document the adapter refused, thrown between the adapter's own classes
 * and never past it: the adapter answers it as a value, with the reason and the
 * rule's name in the package's own words (`schema`, `duplicate_id`,
 * `signature_policy`, say). Its message is that name; it never quotes the
 * document, a value from it or a library's message, and it keeps no previous
 * exception, which might.
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
