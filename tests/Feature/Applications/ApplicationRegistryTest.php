<?php

declare(strict_types = 1);

namespace Tests\Feature\Applications;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Applications\ApplicationRegistry;
use Tests\TestCase;

/**
 * Feature tests for the application registry.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationRegistry::class)]
final class ApplicationRegistryTest extends TestCase
{
    /**
     * Register two applications.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        config()->set('sso.applications', [
            'web'    => ['redirect_uri' => 'https://app.example.com/sso', 'external_sign_in' => true],
            'mobile' => ['redirect_uri' => 'com.example.app:/sso'],
        ]);
    }

    /**
     * An application is found under exactly its name.
     *
     * @return void
     */
    public function testFindsAnApplicationUnderExactlyItsName(): void
    {
        $registry = app(ApplicationRegistry::class);

        self::assertSame('https://app.example.com/sso', $registry->find('web')?->redirectUri);
        self::assertSame('com.example.app:/sso', $registry->find('mobile')?->redirectUri);
        self::assertNull($registry->find('Web'));
        self::assertNull($registry->find('admin'));
        self::assertNull($registry->find(''));
        self::assertNull($registry->find('web.redirect_uri'));
        self::assertNull($registry->find("web\n"));
    }

    /**
     * Every application, by name, in the order configured.
     *
     * @return void
     */
    public function testListsEveryApplication(): void
    {
        $all = app(ApplicationRegistry::class)->all();

        self::assertSame(['web', 'mobile'], array_keys($all));
        self::assertSame('web', $all['web']->name);
        self::assertSame('mobile', $all['mobile']->name);

        config()->set('sso.applications', []);

        self::assertSame([], app(ApplicationRegistry::class)->all());
    }

    /**
     * The configuration is read on each call, never kept.
     *
     * @return void
     */
    public function testReadsTheConfigurationOnEachCall(): void
    {
        $registry = app(ApplicationRegistry::class);

        self::assertNull($registry->find('admin'));

        config()->set('sso.applications.admin', ['redirect_uri' => 'https://admin.example.com/sso']);

        self::assertSame('https://admin.example.com/sso', app(ApplicationRegistry::class)->find('admin')?->redirectUri);
    }

    /**
     * A malformed block or application fails closed only when it is read.
     *
     * @return void
     */
    public function testAMalformedConfigurationFailsClosed(): void
    {
        config()->set('sso.applications.admin', ['redirect_uri' => 'http://admin.example.com/sso']);

        $registry = app(ApplicationRegistry::class);

        self::assertSame('web', $registry->find('web')?->name);

        try {
            $registry->find('admin');
            self::fail('A malformed application was read.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('`sso.applications.admin.redirect_uri` must be an exact redirect URI', $exception->getMessage());
        }

        config()->set('sso.applications', 'web');

        $this->expectExceptionObject(new \InvalidArgumentException('`sso.applications` must be an array of applications, by name.'));

        $registry->all();
    }
}
