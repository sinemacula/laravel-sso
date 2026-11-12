<?php

declare(strict_types = 1);

namespace Tests\Integration\Examples\Operations;

use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\Notification as Notifications;

/**
 * The application's security team, notified on demand by mail since it is no
 * user of the application.
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
