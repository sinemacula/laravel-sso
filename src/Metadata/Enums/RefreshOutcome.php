<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Metadata\Enums;

/**
 * How a refresh of one connection's metadata ended (SSO-2.8, SSO-11.12).
 *
 * The values are stable once released: a value is never renamed or reused.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
enum RefreshOutcome: string
{
    // The metadata was fetched, validated whole and applied; the next refresh
    // is due after the refresh interval
    case REFRESHED = 'refreshed';

    // The fetch was refused or failed, or the metadata was refused; the last
    // good settings are kept and the next refresh backs off
    case FAILED = 'failed';

    // The connection's trust, its anchors or its metadata changed while the
    // metadata was fetched, so nothing was written
    case CONFLICT = 'conflict';

    // An administrator's refresh found another server's claim on the
    // connection, so it did not run
    case IN_PROGRESS = 'in_progress';

    // An administrator's refresh found the connection's metadata limit full, so
    // it did not run
    case RATE_LIMITED = 'rate_limited';

    // A scheduled refresh found the connection claimed or refreshed by another
    // server since it was listed, or no longer due, so it did not run
    case SKIPPED = 'skipped';

    // An administrator's refresh named no such connection, one whose protocol
    // is off or that has no URL to fetch, or came with a stale authentication
    // for a connection the schedule would not refresh
    case REFUSED = 'refused';
}
