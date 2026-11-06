<?php

declare(strict_types = 1);

namespace Tests\Feature\Database;

use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\Event;
use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Database\CiphertextWrite;
use SineMacula\Laravel\Sso\Models\Connection;
use Tests\TestCase;

/**
 * Feature tests for the save of a model whose write carries a ciphertext
 * (SSO-2.5, SSO-11.9): a failed write that binds the ciphertext is a
 * `RuntimeException` that names only the SQLSTATE and chains nothing, while a
 * write that binds none is left to Laravel's own `QueryException`.
 *
 * Each test starts without the package's tables, those an earlier test kept
 * dropped, and only a test that needs them has them, so a write fails on every
 * engine otherwise.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CiphertextWrite::class)]
final class CiphertextWriteTest extends TestCase
{
    /** @var string The ciphertext no failure may quote. */
    private const string CIPHERTEXT = '{"client_secret":"the-ciphertext-under-test"}';

    /** @var string The failure the write is given. */
    private const string FAILURE = 'The connection\'s secrets could not be written';

    /**
     * Drop the tables an earlier test kept, so each test starts without them.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->dropKeptTables();
    }

    /**
     * A failed write that binds the ciphertext is a `RuntimeException` with the
     * failure and the driver's SQLSTATE, which quotes no ciphertext and chains
     * nothing that does.
     *
     * @return void
     */
    public function testAFailedWriteOfTheCiphertextQuotesNothingOfIt(): void
    {
        $thrown = null;

        try {
            CiphertextWrite::save(self::connection(self::CIPHERTEXT), 'secrets', self::FAILURE);
        } catch (\RuntimeException $exception) {
            $thrown = $exception;
        }

        self::assertNotNull($thrown);
        self::assertNotInstanceOf(QueryException::class, $thrown);
        self::assertMatchesRegularExpression('/^The connection\'s secrets could not be written \(SQLSTATE [0-9A-Z]{5}\)\.$/', $thrown->getMessage());
        self::assertStringNotContainsString('the-ciphertext-under-test', $thrown->getMessage());
        self::assertNull($thrown->getPrevious());
    }

    /**
     * A failure that gives no SQLSTATE is named `unknown`, never by what it
     * says.
     *
     * @return void
     */
    public function testAFailureWithoutASqlstateIsNamedUnknown(): void
    {
        Event::listen('eloquent.saving: ' . Connection::class, static function (): never {
            throw new QueryException('testing', 'insert into sso_connections values (?)', [self::CIPHERTEXT], new \RuntimeException('Failing row contains ' . self::CIPHERTEXT));
        });

        $this->expectExceptionObject(new \RuntimeException(self::FAILURE . ' (SQLSTATE unknown).'));

        CiphertextWrite::save(self::connection(self::CIPHERTEXT), 'secrets', self::FAILURE);
    }

    /**
     * A write that binds no ciphertext, the column being `null`, is left to
     * Laravel's own `QueryException`.
     *
     * @return void
     */
    public function testAFailedWriteOfNoCiphertextIsLeftAsItIs(): void
    {
        $this->expectException(QueryException::class);

        CiphertextWrite::save(self::connection(null), 'secrets', self::FAILURE);
    }

    /**
     * A write that does not change the ciphertext column binds none, and is
     * left to Laravel's own `QueryException`.
     *
     * @return void
     */
    public function testAFailedWriteThatLeavesTheCiphertextIsLeftAsItIs(): void
    {
        $connection = self::connection(self::CIPHERTEXT)->forceFill(['id' => '01jbunknownconnection00000']);

        $connection->syncOriginal();
        $connection->exists = true;
        $connection->forceFill(['display_name' => 'Renamed']);

        $this->expectException(QueryException::class);

        CiphertextWrite::save($connection, 'secrets', self::FAILURE);
    }

    /**
     * A write that succeeds is saved, ciphertext and all.
     *
     * @return void
     */
    public function testASuccessfulWriteIsSaved(): void
    {
        $this->usePackageTables();

        $connection = self::connection(self::CIPHERTEXT);

        CiphertextWrite::save($connection, 'secrets', self::FAILURE);

        self::assertTrue($connection->exists);
        self::assertSame(self::CIPHERTEXT, Connection::query()->findOrFail($connection->id)->secrets);
    }

    /**
     * A new connection with the secrets column given.
     *
     * @param  ?string  $secrets
     * @return \SineMacula\Laravel\Sso\Models\Connection
     */
    private static function connection(?string $secrets): Connection
    {
        return (new Connection)->forceFill([
            'tenant_id'    => 'tenant-1',
            'protocol'     => 'oidc',
            'display_name' => 'Example',
            'secrets'      => $secrets,
        ]);
    }
}
