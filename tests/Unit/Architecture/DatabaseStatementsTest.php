<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Database\MigrationCollisionGuard;
use Tests\Concerns\ScansLibraryNames;

/**
 * Architecture tests holding the package's code to reading and writing rows.
 * Only the migrations' collision guard may name the schema.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(MigrationCollisionGuard::class)]
final class DatabaseStatementsTest extends TestCase
{
    use ScansLibraryNames;

    /** @var string A name of the schema builder or its facade, however imported. */
    private const string SCHEMA_NAME = '/^\\\?(?:Illuminate\\\Database\\\Schema\\\|(?:Illuminate\\\Support\\\Facades\\\)?Schema$)/';

    /** @var string The one class that may name the schema, for the migrations. */
    private const string SCHEMA_OWNER = 'src/Database/MigrationCollisionGuard.php';

    /** @var list<string> The methods that run raw statements or reach past the query builder. */
    private const array STATEMENT_METHODS = ['statement', 'unprepared', 'affectingstatement', 'getschemabuilder', 'getpdo', 'getreadpdo', 'getrawpdo', 'getrawreadpdo'];

    /**
     * Rows of `[path]`: every PHP file the package ships.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideSources(): iterable
    {
        foreach (array_keys(self::shippedSources()) as $path) {
            yield $path => [$path];
        }
    }

    /**
     * Only the migrations' guard names the schema, and only its builder.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testOnlyTheMigrationsGuardNamesTheSchema(string $path): void
    {
        $expected = $path === self::SCHEMA_OWNER ? ['Illuminate\Database\Schema\Builder'] : [];

        self::assertSame($expected, array_column(self::scannedNames(self::shippedSources()[$path], self::SCHEMA_NAME), 0), "{$path} names the schema.");
    }

    /**
     * Nothing runs a statement of its own or reaches past the query builder.
     *
     * @param  string  $path
     * @return void
     */
    #[DataProvider('provideSources')]
    public function testNothingRunsAStatementOfItsOwn(string $path): void
    {
        self::assertSame([], self::statementCalls(self::shippedSources()[$path]), "{$path} runs a statement of its own.");
    }

    /**
     * The scans catch every form of schema name and raw statement, and skip
     * comments, declarations and lookalike names.
     *
     * @return void
     */
    public function testTheScansCatchEachWayOfLeavingRows(): void
    {
        $source = <<<'PHP'
            <?php
            use Illuminate\Support\Facades\Schema;
            use Illuminate\Database\Schema\Blueprint;
            \Schema::drop('x');
            $connection->statement('CREATE TABLE x (id int)');
            DB::unprepared('DROP TABLE x');
            $connection->affectingStatement('TRUNCATE x', []);
            $connection->getSchemaBuilder()->drop('x');
            $connection?->getPdo()->exec('LOCK TABLES x WRITE');
            // $connection->statement() in a comment
            function statement(): void {}
            $schemaName = new SchemaDateTime;
            PHP;

        self::assertSame(['Illuminate\Support\Facades\Schema', 'Illuminate\Database\Schema\Blueprint', '\Schema'], array_column(self::scannedNames($source, self::SCHEMA_NAME), 0));
        self::assertSame(['statement', 'unprepared', 'affectingstatement', 'getschemabuilder', 'getpdo'], self::statementCalls($source));
    }

    /**
     * The statement methods the source calls, in order, by lower-case name.
     *
     * @param  string  $source
     * @return list<string>
     */
    private static function statementCalls(string $source): array
    {
        $tokens = array_values(array_filter(
            token_get_all($source),
            static fn ($token): bool => !is_array($token) || !in_array($token[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true),
        ));
        $found = [];

        foreach ($tokens as $index => $token) {

            $previous = $tokens[$index - 1] ?? null;
            $called   = is_array($token)    && $token[0] === T_STRING && ($tokens[$index + 1] ?? null) === '(';
            $member   = is_array($previous) && in_array($previous[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true);

            if (!$called || !$member || !in_array(strtolower($token[1]), self::STATEMENT_METHODS, true)) {
                continue;
            }

            $found[] = strtolower($token[1]);
        }

        return $found;
    }
}
