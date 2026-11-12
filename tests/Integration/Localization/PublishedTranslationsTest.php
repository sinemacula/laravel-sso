<?php

declare(strict_types = 1);

namespace Tests\Integration\Localization;

use Illuminate\Filesystem\Filesystem;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Localization\Enums\Message;
use SineMacula\Laravel\Sso\Localization\Messages;
use SineMacula\Laravel\Sso\SsoServiceProvider;
use Tests\TestCase;

/**
 * Integration tests for publishing the translations and overriding the
 * published lines.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(Messages::class)]
#[CoversClass(SsoServiceProvider::class)]
final class PublishedTranslationsTest extends TestCase
{
    /**
     * Lines the application changes replace the package's. The lang directory
     * is moved since parallel workers share it.
     *
     * @return void
     */
    public function testPublishedTranslationsAreOverriddenByTheApplication(): void
    {
        /** @var \Illuminate\Foundation\Application $app */
        $app       = $this->app;
        $langPath  = $app->langPath();
        $directory = sys_get_temp_dir() . '/' . uniqid('laravel-sso-', true);
        $published = $directory . '/vendor/sso';
        $files     = new Filesystem;

        [$publishes, $groups] = [ServiceProvider::$publishes, ServiceProvider::$publishGroups];

        $files->ensureDirectoryExists($directory);

        try {
            $app->useLangPath($directory);

            (new SsoServiceProvider($app))->boot();

            self::assertSame(0, Artisan::call('vendor:publish', ['--tag' => 'sso-lang']));

            self::assertFileEquals(dirname(__DIR__, 3) . '/lang/en/messages.php', $published . '/en/messages.php');

            $files->put($published . '/en/messages.php', "<?php\n\nreturn ['post_navigation' => ['continue' => 'Carry on']];\n");
            $files->ensureDirectoryExists($published . '/fr');
            $files->put($published . '/fr/messages.php', "<?php\n\nreturn ['post_navigation' => ['continue' => 'Continuer']];\n");

            $this->forgetTranslator();

            /** @var \SineMacula\Laravel\Sso\Localization\Messages $messages */
            $messages = $app->make(Messages::class);

            self::assertSame('Carry on', $messages->get(Message::POST_NAVIGATION_CONTINUE));
            self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE));
            self::assertSame('Continuer', $messages->get(Message::POST_NAVIGATION_CONTINUE, [], 'fr'));
            self::assertSame('Signing you in', $messages->get(Message::POST_NAVIGATION_TITLE, [], 'fr'));
        } finally {
            [ServiceProvider::$publishes, ServiceProvider::$publishGroups] = [$publishes, $groups];

            $app->useLangPath($langPath);

            $this->forgetTranslator();

            $files->deleteDirectory($directory);
        }
    }

    /**
     * Forget the translator and its loader so the next resolution reads the
     * lang directory afresh.
     *
     * @return void
     */
    private function forgetTranslator(): void
    {
        $this->app?->forgetInstance('translation.loader');
        $this->app?->forgetInstance('translator');
    }
}
