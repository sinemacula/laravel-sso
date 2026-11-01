<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Applications\ApplicationAdmission;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;

/**
 * Unit tests for a refused admission: the one reason, and no application.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationAdmission::class)]
final class ApplicationAdmissionTest extends TestCase
{
    /**
     * A refusal is always `application_not_allowed`, whatever refused it.
     *
     * @return void
     */
    public function testARefusalIsApplicationNotAllowed(): void
    {
        $refused = ApplicationAdmission::notAllowed();

        self::assertTrue($refused->isRefused());
        self::assertFalse($refused->isAdmitted());
        self::assertNull($refused->application);
        self::assertSame(FailureReason::APPLICATION_NOT_ALLOWED, $refused->reason);
    }
}
