<?php

declare(strict_types = 1);

namespace Tests\Feature\Metadata;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Metadata\MetadataCheck;
use Tests\Concerns\RunsConfigurationChecks;
use Tests\TestCase;

/**
 * Feature tests for `[metadata]`: checked while the package is in use, and the
 * queue a scheduled refresh is sent to checked only while the
 * `metadata_refresh` feature is on.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MetadataCheck::class)]
final class MetadataCheckTest extends TestCase
{
    use RunsConfigurationChecks;

    /**
     * Not checked while the package is not in use; passes with the defaults
     * once it is.
     *
     * @return void
     */
    public function testAppliesOnlyWhileThePackageIsInUse(): void
    {
        self::assertNull($this->problemsOf(MetadataCheck::class));

        $this->useThePackage();

        self::assertSame([], $this->problemsOf(MetadataCheck::class));
    }

    /**
     * A malformed queue name is a problem while the scheduled refresh is on,
     * and not checked once it is off.
     *
     * @return void
     */
    public function testChecksTheQueueOnlyWhileTheScheduledRefreshIsOn(): void
    {
        $this->useThePackage();

        config()->set('sso.metadata.queue.name', ['slow']);

        self::assertSame(['sso.metadata.queue.name must be a name of at most 255 bytes, or null.'], $this->problemsOf(MetadataCheck::class));

        config()->set('sso.features.metadata_refresh', false);

        self::assertSame([], $this->problemsOf(MetadataCheck::class));
    }
}
