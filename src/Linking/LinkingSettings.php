<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Linking;

use Illuminate\Contracts\Config\Repository;
use SineMacula\Laravel\Sso\Config\IntegerSetting;

/**
 * Reads `sso.linking`.
 *
 * Entra's `common` and `organizations` are authorities, not issuers, so they
 * are deliberately not in `SHARED_ISSUERS`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class LinkingSettings
{
    /** @var array<string, string> Shared issuers, each with its organisation claim. */
    public const array SHARED_ISSUERS = [
        'https://accounts.google.com' => 'hd',
        'accounts.google.com'         => 'hd',
        'https://slack.com'           => 'https://slack.com/team_id',
    ];

    /** @var int The verified response's validity when none is configured, in seconds. */
    private const int DEFAULT_VERIFIED_RESULT_AGE = 120;

    /** @var int The least validity a verified response may be configured with, in seconds. */
    private const int MIN_VERIFIED_RESULT_AGE = 5;

    /** @var int The most validity a verified response may be configured with, in seconds. */
    private const int MAX_VERIFIED_RESULT_AGE = 300;

    /** @var int The evidence's maximum age when none is configured, in seconds. */
    private const int DEFAULT_EVIDENCE_AGE = 900;

    /** @var int The least the evidence's maximum age may be configured to, in seconds. */
    private const int MIN_EVIDENCE_AGE = 60;

    /** @var int The most the evidence's maximum age may be configured to, in seconds. */
    private const int MAX_EVIDENCE_AGE = 3600;

    /**
     * Constructor.
     *
     * @param  \Illuminate\Contracts\Config\Repository  $config
     */
    public function __construct(

        /** The configuration read. */
        private Repository $config,
    ) {}

    /**
     * How long a verified response may keep finishing, in seconds; never past
     * the request's own expiry.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function verifiedResultMaxAgeSeconds(): int
    {
        $key = 'sso.linking.verified_result_max_age_seconds';

        return IntegerSetting::read($this->config, $key, self::DEFAULT_VERIFIED_RESULT_AGE, self::MIN_VERIFIED_RESULT_AGE, self::MAX_VERIFIED_RESULT_AGE);
    }

    /**
     * The longest time since the provider's authentication evidence may be
     * accepted, in seconds.
     *
     * @return int
     *
     * @throws \InvalidArgumentException
     */
    public function evidenceMaxAgeSeconds(): int
    {
        return IntegerSetting::read($this->config, 'sso.linking.evidence_max_age_seconds', self::DEFAULT_EVIDENCE_AGE, self::MIN_EVIDENCE_AGE, self::MAX_EVIDENCE_AGE);
    }

    /**
     * The configured shared issuers, with the built-in ones over them so none
     * is downgraded.
     *
     * @return array<string, string>
     *
     * @throws \InvalidArgumentException
     */
    public function sharedIssuers(): array
    {
        $configured = $this->config->get('sso.linking.shared_issuers', []);

        if (!is_array($configured)) {
            throw new \InvalidArgumentException('sso.linking.shared_issuers must map each issuer to its organisation claim.');
        }

        foreach ($configured as $issuer => $claim) {
            if (!is_string($issuer) || $issuer === '' || !is_string($claim) || $claim === '') {
                throw new \InvalidArgumentException('sso.linking.shared_issuers must map each issuer to its organisation claim.');
            }
        }

        return [...$configured, ...self::SHARED_ISSUERS];
    }
}
