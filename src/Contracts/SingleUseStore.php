<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Contracts;

use Carbon\CarbonImmutable;
use SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome;

/**
 * Single-use store contract (SSO-11.5): records a key once in its namespace
 * until an expiry, atomically and shared by every server, and answers whether
 * it was new. It backs SAML assertion ids (keyed by connection and issuer,
 * SSO-6.6), authorisation requests (SSO-5.1) and handoff codes (SSO-9.2).
 *
 * Only `recorded` lets a flow proceed. An implementation answers `seen` only
 * when it knows the key is held; on any error, timeout or answer it doubts it
 * throws, and the flow is refused as a server error (SSO-11.4), never passed.
 * It must be atomic (two concurrent records of one key: exactly one
 * `recorded`), shared by every server and process, keep each key until its
 * expiry, and read from the write connection or primary (SSO-11.3). A key whose
 * expiry has passed may be recorded again. The default records keys in the
 * database under a unique index on the storage connection; an application may
 * bind another store only if it meets all of this. A store must record within
 * the caller's transaction for a rolled-back redemption to be retried; a record
 * kept when that transaction rolls back makes the retry `replayed`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
interface SingleUseStore
{
    /**
     * Record the key in the namespace until the expiry, unless it is held
     * there: `recorded` when it was not, `seen` when it was.
     *
     * The namespace says what the key is (`saml_assertion`,
     * `authorization_request`, `handoff_code`): 1 to 64 characters of lower
     * case letters, digits, `_`, `.`, `:` and `-`. The key is any non-empty
     * string, scoped by the caller where it must be (an assertion id joined
     * with its connection and issuer, say), and may be a secret (a handoff
     * code): the store keeps only a digest of it. A malformed namespace, an
     * empty key or an expiry already past is an `InvalidArgumentException`;
     * any failure to answer with certainty is thrown, never answered.
     *
     * @param  string  $namespace
     * @param  string  $key
     * @param  \Carbon\CarbonImmutable  $until
     * @return \SineMacula\Laravel\Sso\SingleUse\Enums\SingleUseOutcome
     *
     * @throws \InvalidArgumentException
     * @throws \Throwable
     *
     * @phpstan-impure
     */
    public function record(string $namespace, #[\SensitiveParameter] string $key, CarbonImmutable $until): SingleUseOutcome;
}
