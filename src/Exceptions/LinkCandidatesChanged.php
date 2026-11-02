<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Exceptions;

/**
 * What a transaction in the package's linking lock order is refused with when
 * the connections its plain read found no longer cover an identity's verified
 * domain links under the lock (SSO-8.8, `docs/design/linking.md`): a connection
 * cannot be locked now without breaking the order, so nothing is written, and
 * the caller retries its whole transaction, whose new snapshot finds them. It
 * names no identity, link or connection.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final class LinkCandidatesChanged extends \RuntimeException
{
    /**
     * The refusal of a transaction whose candidates changed.
     *
     * @return self
     */
    public static function retryWhole(): self
    {
        return new self('An identity\'s verified domain links changed before they were locked; retry the whole transaction.');
    }
}
