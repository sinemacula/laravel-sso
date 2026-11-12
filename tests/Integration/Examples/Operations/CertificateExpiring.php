<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Operations;

use Carbon\CarbonImmutable;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

/**
 * The application's notification that a connection's key or certificate needs
 * rotating.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class CertificateExpiring extends Notification
{
    /**
     * Constructor.
     *
     * @param  ?string  $connectionId
     * @param  string  $fingerprint
     * @param  \Carbon\CarbonImmutable  $notAfter
     * @param  int  $thresholdDays
     */
    public function __construct(

        /** The connection the key or certificate belongs to. */
        public readonly ?string $connectionId,

        /** Its lower-case hex SHA-256 fingerprint. */
        public readonly string $fingerprint,

        /** When its validity ends. */
        public readonly CarbonImmutable $notAfter,

        /** The threshold reached, in days before the end of validity: 0 once it has ended. */
        public readonly int $thresholdDays,
    ) {}

    /**
     * The channels the notification is sent on.
     *
     * @param  object  $notifiable
     * @return list<string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * The mail the security team reads.
     *
     * @param  object  $notifiable
     * @return \Illuminate\Notifications\Messages\MailMessage
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
            ->subject(sprintf('An SSO certificate reached its %d-day expiry threshold', $this->thresholdDays))
            ->line(sprintf('Connection %s holds the certificate %s.', $this->connectionId ?? 'unknown', $this->fingerprint))
            ->line(sprintf('Its validity ends %s.', $this->notAfter->utc()->format('Y-m-d\TH:i:s\Z')));
    }
}
