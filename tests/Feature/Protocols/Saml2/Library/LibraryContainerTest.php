<?php

declare(strict_types = 1);

namespace Tests\Feature\Protocols\Saml2\Library;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use SimpleSAML\SAML2\Compat\AbstractContainer;
use SimpleSAML\SAML2\Compat\ContainerSingleton;
use SimpleSAML\SAML2\Compat\MockContainer;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\HardenedParser;
use SineMacula\Laravel\Sso\Protocols\Saml2\Library\LibraryContainer;
use Tests\TestCase;

/**
 * Tests of the container the SAML library reads its process-wide services from.
 *
 * The library is named here only to observe its container.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(LibraryContainer::class)]
#[CoversClass(HardenedParser::class)]
final class LibraryContainerTest extends TestCase
{
    /**
     * The package sets its own container once and keeps it however often it is
     * ensured again.
     *
     * @return void
     */
    #[RunInSeparateProcess]
    public function testTheContainerIsSetOnceAndKept(): void
    {
        self::assertFalse((new \ReflectionProperty(ContainerSingleton::class, 'container'))->isInitialized());

        LibraryContainer::ensure();

        $set = ContainerSingleton::getInstance();

        LibraryContainer::ensure();
        LibraryContainer::ensure();

        self::assertInstanceOf(LibraryContainer::class, $set);
        self::assertSame($set, ContainerSingleton::getInstance());
    }

    /**
     * A container something else set is refused, naming the problem, and left
     * as it is; the package's own set before is kept.
     *
     * @return void
     */
    public function testAContainerSomethingElseSetIsRefused(): void
    {
        $foreign  = new MockContainer;
        $previous = self::setContainer($foreign);

        try {
            LibraryContainer::ensure();
            self::fail('A container something else set was used.');
        } catch (\LogicException $exception) {
            self::assertSame(
                'The SAML library\'s process-wide container is already set to [' . MockContainer::class . '], not the package\'s own: '
                . 'the package runs SAML only through the container it sets itself.',
                $exception->getMessage(),
            );
            self::assertSame($foreign, ContainerSingleton::getInstance());
        } finally {
            ContainerSingleton::setContainer($previous);
        }

        $own = new LibraryContainer;

        self::setContainer($own);

        try {
            LibraryContainer::ensure();

            self::assertSame($own, ContainerSingleton::getInstance());
        } finally {
            ContainerSingleton::setContainer($previous);
        }
    }

    /**
     * A parse refuses to run through a container something else set.
     *
     * @return void
     */
    public function testAParseRefusesAContainerSomethingElseSet(): void
    {
        $previous = self::setContainer(new MockContainer);

        try {
            (new HardenedParser)->load('<x/>', 4);
            self::fail('A parse ran through a container something else set.');
        } catch (\Throwable $exception) {
            self::assertInstanceOf(\LogicException::class, $exception);
            self::assertStringContainsString('not the package\'s own', $exception->getMessage());
        } finally {
            ContainerSingleton::setContainer($previous);
        }
    }

    /**
     * The container discards logs and debug messages, and refuses every service
     * the package never uses.
     *
     * @return void
     */
    public function testTheContainerRefusesWhatThePackageNeverUses(): void
    {
        $container = new LibraryContainer;

        $container->debugMessage('<samlp:Response/>', 'in');
        $container->getLogger()->error('discarded');

        $refusals = [
            'blacklist'           => static fn () => $container->setBlacklistedAlgorithms([]),
            'redirects'           => static fn () => $container->getPOSTRedirectURL('https://example.com'),
            'temporary directory' => static fn () => $container->getTempDir(),
            'files'               => static fn () => $container->writeFile('a', 'b'),
            'clock'               => static fn () => $container->getClock(),
            'inflate size limit'  => static fn () => $container->getInflateSizeLimit(),
        ];

        foreach ($refusals as $service => $call) {
            try {
                $call();
                self::fail("The container answered its {$service}.");
            } catch (\LogicException $exception) {
                self::assertSame("The SAML adapter never asks the library for its {$service}.", $exception->getMessage());
            }
        }
    }

    /**
     * Set the library's container, and answer the package's own that was set
     * before, set first when none was, to restore afterwards.
     *
     * @param  \SimpleSAML\SAML2\Compat\AbstractContainer  $container
     * @return \SimpleSAML\SAML2\Compat\AbstractContainer
     */
    private static function setContainer(AbstractContainer $container): AbstractContainer
    {
        LibraryContainer::ensure();

        $previous = ContainerSingleton::getInstance();

        ContainerSingleton::setContainer($container);

        return $previous;
    }
}
