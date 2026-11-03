<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\RedeemingAHandoff;

use Carbon\CarbonImmutable;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;
use SineMacula\Laravel\Sso\Contracts\Clock;
use SineMacula\Laravel\Sso\Contracts\HandoffIssuer;
use SineMacula\Laravel\Sso\Database\StorageConnection;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Flows\Enums\Purpose;
use SineMacula\Laravel\Sso\Flows\S256Challenge;
use SineMacula\Laravel\Sso\Handoffs\HandoffCode;
use SineMacula\Laravel\Sso\Handoffs\HandoffGrant;
use SineMacula\Laravel\Sso\Handoffs\IssuedHandoff;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * An application's own handoff store of `docs/guides/redeeming-a-handoff.md`
 * (SSO-9.2, SSO-12.5), bound to `Contracts\HandoffIssuer` in place of the
 * package's: it issues each code inside the completion's transaction, into the
 * application's own table on the package's storage connection, keeping only the
 * code's digest, the verified result encrypted, and everything else the grant
 * names, the connection's trust version and the session's latest end among
 * them, as the contract requires (the latest end to the whole second, as the
 * package's own store keeps it, so never later); it reads a code back plainly,
 * with both; and it consumes one atomically, exactly once, inside the
 * redeemer's transaction, then checks it as the package checks its own (the
 * expiry, the purpose and the verifier).
 *
 * It keeps nothing of one call for the next (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class OwnHandoffCodes implements HandoffIssuer
{
    /** @var string The application's own table of codes. */
    public const string TABLE = 'app_handoff_codes';

    /**
     * Read the time from the package's clock.
     *
     * @param  \SineMacula\Laravel\Sso\Contracts\Clock  $clock
     */
    public function __construct(

        /** The clock a code is consumed and expired by. */
        private Clock $clock,
    ) {}

    /**
     * Issue a new code for the grant, inside the completion's transaction.
     *
     * @param  \SineMacula\Laravel\Sso\Handoffs\HandoffGrant  $grant
     * @return \SineMacula\Laravel\Sso\Handoffs\IssuedHandoff
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    public function issue(HandoffGrant $grant): IssuedHandoff
    {
        $code      = HandoffCode::generate();
        $reference = strtolower((string) Str::ulid());

        self::table()->insert([
            'id'                   => $reference,
            'code_digest'          => $code->digest(),
            'result'               => Crypt::encryptString(serialize($grant->result)),
            'challenge'            => $grant->challenge->value,
            'linked_identity_type' => $grant->linkedIdentity?->type,
            'linked_identity_id'   => $grant->linkedIdentity?->id,
            'link_id'              => $grant->linkId,
            'identity_type'        => $grant->identity?->type,
            'identity_id'          => $grant->identity?->id,
            'session_id'           => $grant->sessionId,
            'reservation_id'       => $grant->reservationId,
            'trust_version'        => $grant->trustVersion,
            'session_not_after'    => $grant->sessionNotAfter?->getTimestamp(),
            'expires_at'           => $grant->expiresAt->getTimestamp(),
        ]);

        return new IssuedHandoff($code, $grant->expiresAt->startOfSecond(), $reference);
    }

    /**
     * The code the value is, read plainly, or `null` when it is not a code this
     * store issued.
     *
     * @param  string  $value
     * @return ?\Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCode
     *
     * @throws \UnexpectedValueException
     */
    public function find(#[\SensitiveParameter] string $value): ?OwnHandoffCode
    {
        if (!HandoffCode::isWellFormed($value)) {
            return null;
        }

        $row = self::table()->where('code_digest', HandoffCode::fromString($value)->digest())->first();

        return $row === null ? null : self::code((array) $row);
    }

    /**
     * Consume the code atomically, inside the redeemer's transaction, and
     * answer why it is refused: `replayed` when it was consumed before, and
     * nothing is spent now; otherwise it is spent, and refused when it has
     * expired, was issued for another purpose than the one given, or the
     * verifier is not its own; `null` when it is accepted.
     *
     * @param  \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCode  $code
     * @param  \SineMacula\Laravel\Sso\Flows\Enums\Purpose  $purpose
     * @param  string  $verifier
     * @return ?\SineMacula\Laravel\Sso\Events\Enums\FailureReason
     */
    public function consume(OwnHandoffCode $code, Purpose $purpose, #[\SensitiveParameter] string $verifier): ?FailureReason
    {
        $now   = $this->clock->now()->getTimestamp();
        $spent = self::table()->where('id', $code->reference)->whereNull('consumed_at')->update(['consumed_at' => $now]);

        if ($spent !== 1) {
            return FailureReason::REPLAYED;
        }

        return match (true) {
            $now >= $code->expiresAt            => FailureReason::HANDOFF_EXPIRED,
            $code->result->purpose !== $purpose => FailureReason::PURPOSE_MISMATCH,
            !$code->isVerifiedBy($verifier)     => FailureReason::VERIFIER_MISMATCH,
            default                             => null,
        };
    }

    /**
     * The code a row of the table holds.
     *
     * @param  array<string, mixed>  $row
     * @return \Tests\Integration\Examples\RedeemingAHandoff\OwnHandoffCode
     *
     * @throws \UnexpectedValueException
     */
    private static function code(array $row): OwnHandoffCode
    {
        return new OwnHandoffCode(
            reference: (string) self::value($row, 'id'),
            result: self::result((string) self::value($row, 'result')),
            challenge: S256Challenge::fromString((string) self::value($row, 'challenge')),
            expiresAt: (int) self::value($row, 'expires_at'),
            linkedIdentity: IdentityReference::fromColumns(self::value($row, 'linked_identity_type'), self::value($row, 'linked_identity_id')),
            linkId: self::value($row, 'link_id'),
            identity: IdentityReference::fromColumns(self::value($row, 'identity_type'), self::value($row, 'identity_id')),
            sessionId: self::value($row, 'session_id'),
            reservationId: self::value($row, 'reservation_id'),
            trustVersion: self::integer($row, 'trust_version'),
            sessionNotAfter: self::instant($row, 'session_not_after'),
        );
    }

    /**
     * The verified result a code carries, decrypted and restored, every part
     * checked again.
     *
     * @param  string  $stored
     * @return \SineMacula\Laravel\Sso\Results\VerifiedResult
     *
     * @throws \UnexpectedValueException
     */
    private static function result(string $stored): VerifiedResult
    {
        $result = unserialize(Crypt::decryptString($stored), ['allowed_classes' => [VerifiedResult::class]]);

        if (!$result instanceof VerifiedResult) {
            throw new \UnexpectedValueException('A stored handoff code carries no verified result.');
        }

        return $result;
    }

    /**
     * A column of the row as a string, or `null` when it holds none.
     *
     * @param  array<string, mixed>  $row
     * @param  string  $column
     * @return ?string
     */
    private static function value(array $row, string $column): ?string
    {
        $value = $row[$column] ?? null;

        return is_scalar($value) ? (string) $value : null;
    }

    /**
     * A column of the row as an integer, or `null` when it holds none.
     *
     * @param  array<string, mixed>  $row
     * @param  string  $column
     * @return ?int
     */
    private static function integer(array $row, string $column): ?int
    {
        $value = self::value($row, $column);

        return $value === null ? null : (int) $value;
    }

    /**
     * A column of the row, seconds since the epoch, as an instant in UTC, or
     * `null` when it holds none.
     *
     * @param  array<string, mixed>  $row
     * @param  string  $column
     * @return ?\Carbon\CarbonImmutable
     */
    private static function instant(array $row, string $column): ?CarbonImmutable
    {
        $seconds = self::integer($row, $column);

        return $seconds === null ? null : CarbonImmutable::createFromTimestampUTC($seconds);
    }

    /**
     * The application's table of codes, on the package's storage connection.
     *
     * @return \Illuminate\Database\Query\Builder
     */
    private static function table(): Builder
    {
        return DB::connection(StorageConnection::name())->table(self::TABLE);
    }
}
