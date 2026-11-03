<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Operations;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Notification as Notifications;

/**
 * The application's security team, which the operations guide's key expiry
 * listener tells to rotate (SSO-2.6, SSO-12.5): a notification to it is sent on
 * demand to the team's address, since the team is no user of the application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class SecurityTeam
{
    /** @var string Where the team is told. */
    public const string ADDRESS = 'security@example.com';

    /**
     * Send the notification to the team, by mail.
     *
     * @param  \Illuminate\Notifications\Notification  $notification
     * @return void
     */
    public static function notify(Notification $notification): void
    {
        Notifications::route('mail', self::ADDRESS)->notify($notification);
    }
}
