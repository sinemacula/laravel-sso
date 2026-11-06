<?php

declare(strict_types = 1);

namespace Tests\Feature\Completion\Stages;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Completion\CompletionState;
use SineMacula\Laravel\Sso\Completion\Stages\ResolveLink;
use SineMacula\Laravel\Sso\Contracts\Linker;
use SineMacula\Laravel\Sso\Http\ClientContext;
use SineMacula\Laravel\Sso\Identities\IdentityReference;
use SineMacula\Laravel\Sso\Links\LinkResolution;
use SineMacula\Laravel\Sso\Protocols\CompletionRequest;
use SineMacula\Laravel\Sso\Results\VerifiedResult;
use Tests\Fixtures\Results\ExampleResults;

/**
 * Feature tests for the link resolution step of a completion: it asks the
 * linking contract about the verified result for the client the completion
 * arrived from, the very context its state carries, and goes on with what the
 * contract resolved.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ResolveLink::class)]
final class ResolveLinkTest extends TestCase
{
    /**
     * The linker is given the state's result and its client, and the stage goes
     * on with the resolution it answered.
     *
     * @return void
     */
    public function testTheLinkerIsAskedForTheStatesClient(): void
    {
        $client   = new ClientContext('203.0.113.7', 'Example/1.0');
        $result   = ExampleResults::full();
        $identity = new IdentityReference('App\Models\User', '7');
        $asked    = self::asked();
        $linker   = self::recordingLinker(LinkResolution::linked($identity, '01jbexamplelink00000000000'), $asked);
        $state    = CompletionState::arrived('01jbexampleconnection00000', new CompletionRequest('GET', '', []), $client)->withResult($result);

        $outcome = (new ResolveLink($linker))->run($state);

        self::assertTrue($outcome->isProceeding());
        self::assertSame($identity, $outcome->state->linkedIdentity);
        self::assertSame([[$result, $client]], $asked->getArrayCopy());
        self::assertSame($client, $outcome->state->client);
    }

    /**
     * A state with no verified result is a `LogicException`, before the linker
     * is asked.
     *
     * @return void
     */
    public function testAStateWithNoResultIsALogicException(): void
    {
        $asked  = self::asked();
        $linker = self::recordingLinker(LinkResolution::absent(), $asked);

        try {
            (new ResolveLink($linker))->run(CompletionState::arrived('01jbexampleconnection00000', new CompletionRequest('GET', '', []), new ClientContext(null, null)));
            self::fail('A state with no result was resolved.');
        } catch (\LogicException $exception) {
            self::assertSame('A link is resolved once the result is verified.', $exception->getMessage());
        }

        self::assertSame([], $asked->getArrayCopy());
    }

    /**
     * A record of what a linker is asked, empty.
     *
     * @return \ArrayObject<int, array{0: \SineMacula\Laravel\Sso\Results\VerifiedResult, 1: \SineMacula\Laravel\Sso\Http\ClientContext}>
     */
    private static function asked(): \ArrayObject
    {
        return new \ArrayObject;
    }

    /**
     * A linker that answers the resolution given and records each result and
     * client it is asked about.
     *
     * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
     * @param  \ArrayObject<int, array{0: \SineMacula\Laravel\Sso\Results\VerifiedResult, 1: \SineMacula\Laravel\Sso\Http\ClientContext}>  $asked
     * @return \SineMacula\Laravel\Sso\Contracts\Linker
     */
    private static function recordingLinker(LinkResolution $resolution, \ArrayObject $asked): Linker
    {
        return new readonly class ($resolution, $asked) implements Linker {
            /**
             * Constructor.
             *
             * @param  \SineMacula\Laravel\Sso\Links\LinkResolution  $resolution
             * @param  \ArrayObject<int, array{0: \SineMacula\Laravel\Sso\Results\VerifiedResult, 1: \SineMacula\Laravel\Sso\Http\ClientContext}>  $asked
             */
            public function __construct(

                /** What every result resolves to. */
                private LinkResolution $resolution,

                /** Each result and client asked about. */
                private \ArrayObject $asked,
            ) {}

            /**
             * Record the result and the client, and answer the resolution.
             *
             * @param  \SineMacula\Laravel\Sso\Results\VerifiedResult  $result
             * @param  \SineMacula\Laravel\Sso\Http\ClientContext  $client
             * @return \SineMacula\Laravel\Sso\Links\LinkResolution
             */
            #[\Override]
            public function resolve(VerifiedResult $result, ClientContext $client): LinkResolution
            {
                $this->asked->append([$result, $client]);

                return $this->resolution;
            }
        };
    }
}
