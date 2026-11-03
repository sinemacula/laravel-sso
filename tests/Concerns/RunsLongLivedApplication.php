<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Container\Container;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Foundation\Application;
use Illuminate\Http\Request;
use Illuminate\Queue\WorkerOptions;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Laravel\Octane\Events\RequestTerminated;
use Laravel\Octane\Octane;
use Laravel\Octane\OctaneServiceProvider;
use Laravel\Octane\RequestContext;
use Laravel\Octane\Testing\Fakes\FakeClient;
use Laravel\Octane\Testing\Fakes\FakeWorker;
use Symfony\Component\HttpFoundation\Response;
use Tests\Fixtures\Octane\BootedApplicationFactory;

/**
 * Keeps one application alive across consecutive requests and jobs, A then B
 * then A, as a server worker and a queue worker do (SSO-11.2), through their
 * real lifecycles and never by rebuilding the application or clearing the
 * package's state to help a test pass.
 *
 * A request goes through the real Octane `Worker`, as Octane's own suite does:
 * the test's booted application, warmed with Octane's default services, is the
 * root application, and each request is served in a clone of it, around which
 * Octane dispatches its listeners, with the flush of the scoped instances among
 * them. Only the server is fake. `serve()` asserts the worker caught no error
 * of its own: a route that throws is the HTTP kernel's to answer, with the 500
 * its exception handler renders, and the next request runs in the same worker.
 *
 * A job goes through the real queue `Worker`, over the database queue, in its
 * real loop, which resets the scope before each job; a job that throws is
 * recorded and the worker goes on, as it does in production.
 *
 * `retainedBy()` is the question behind the harness: it walks every object the
 * root application still holds, and answers each package object or string
 * reached that carries a value of the request or job just finished, and
 * `retainedByStatics()` asks the same of the package's static properties, which
 * neither a sandbox nor a reset of the scope clears. Checking only what a
 * response says would miss what a later request could reach.
 *
 * A test calls `bootLongLivedWorker()` once its routes are registered,
 * `createWorkerQueue()` if it runs jobs, and `dropWorkerQueue()` from its
 * `tearDown()`.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait RunsLongLivedApplication
{
    /** @var string The queue connection the jobs go through. */
    private static string $workerQueueConnection = 'sso_worker_queue';

    /** @var ?\Laravel\Octane\Testing\Fakes\FakeWorker The worker every request is served by. */
    private ?FakeWorker $octaneWorker = null;

    /** @var ?\Laravel\Octane\Testing\Fakes\FakeClient The fake server the worker answers. */
    private ?FakeClient $octaneClient = null;

    /**
     * Register Octane on the test's application, warm it as a worker does at
     * boot, and boot a worker on it.
     *
     * @return void
     */
    protected function bootLongLivedWorker(): void
    {
        $app = $this->longLivedApplication();

        $app->register(OctaneServiceProvider::class);

        $this->octaneClient = new FakeClient([]);
        $this->octaneWorker = new FakeWorker(new BootedApplicationFactory($app), $this->octaneClient);

        $this->octaneWorker->boot();
    }

    /**
     * Serve the request through the worker and return its response, failing the
     * test when the worker itself caught an error.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    protected function serve(Request $request): TestResponse
    {
        $worker = $this->octaneWorker;
        $client = $this->octaneClient;

        self::assertNotNull($worker, 'Boot the worker before serving a request.');
        self::assertNotNull($client);

        $errors    = count($client->errors);
        $responses = count($client->responses);

        $worker->handle($request, new RequestContext(['request' => $request]));

        self::assertSame([], array_slice($client->errors, $errors), 'The Octane worker caught an error.');
        self::assertCount($responses + 1, $client->responses);

        $response = $client->responses[$responses];

        $this->restoreRootApplication($request, $response);

        return TestResponse::fromBaseResponse($response);
    }

    /**
     * A JSON request from a client.
     *
     * @param  string  $method
     * @param  string  $uri
     * @param  array<string, mixed>  $parameters
     * @param  string  $ip
     * @param  array<string, string>  $server
     * @return \Illuminate\Http\Request
     */
    protected static function workerRequest(string $method, string $uri, array $parameters = [], string $ip = '203.0.113.7', array $server = []): Request
    {
        return Request::create($uri, $method, $parameters, server: ['REMOTE_ADDR' => $ip, 'HTTP_ACCEPT' => 'application/json', ...$server]);
    }

    /**
     * Create the database queue's table and point a queue connection at it.
     *
     * @return void
     */
    protected function createWorkerQueue(): void
    {
        config()->set('queue.connections.' . self::$workerQueueConnection, ['driver' => 'database', 'table' => 'sso_worker_jobs', 'queue' => 'default', 'retry_after' => 60]);
        config()->set('queue.default', self::$workerQueueConnection);

        Schema::create('sso_worker_jobs', static function (Blueprint $blueprint): void {
            $blueprint->id();
            $blueprint->string('queue')->index();
            $blueprint->longText('payload');
            $blueprint->unsignedTinyInteger('attempts');
            $blueprint->unsignedInteger('reserved_at')->nullable();
            $blueprint->unsignedInteger('available_at');
            $blueprint->unsignedInteger('created_at');
        });
    }

    /**
     * Drop the database queue's table.
     *
     * @return void
     */
    protected function dropWorkerQueue(): void
    {
        Schema::dropIfExists('sso_worker_jobs');
    }

    /**
     * Run the next queued job in the one queue worker through the loop
     * `queue:work` runs, stopping after that job or on an empty queue: the loop
     * resets the scope before it takes a job. What the loop leaves on the
     * process's signals is put back, so that the suite can still be interrupted
     * and a later fork inherits nothing of it.
     *
     * @return void
     */
    protected function workNextJob(): void
    {
        $options                = new WorkerOptions;
        $options->sleep         = 0;
        $options->maxTries      = 1;
        $options->maxJobs       = 1;
        $options->stopWhenEmpty = true;

        /** @var \Illuminate\Queue\Worker $worker */
        $worker  = $this->longLivedApplication()->make('queue.worker');
        $signals = self::signalHandlers();
        $async   = function_exists('pcntl_async_signals') && pcntl_async_signals();

        try {
            $worker->daemon(self::$workerQueueConnection, 'default', $options);
        } finally {
            self::restoreSignalHandlers($signals, $async);
        }
    }

    /**
     * How many jobs wait in the queue.
     *
     * @return int
     */
    protected function jobsWaiting(): int
    {
        return DB::table('sso_worker_jobs')->count();
    }

    /**
     * Every string the root application still holds, reached from each bound
     * instance through package objects, their properties and arrays, that
     * contains one of the values given: what a later request or job could reach
     * of an earlier one. Each answer names the path it was reached by.
     *
     * @param  list<string>  $values
     * @return list<string>
     */
    protected function retainedBy(array $values): array
    {
        $found = [];
        $seen  = [];

        $instances = (new \ReflectionProperty(Container::class, 'instances'))->getValue($this->longLivedApplication());

        foreach ($instances as $abstract => $instance) {
            $this->walkRetained($instance, (string) $abstract, $values, $seen, $found, 0);
        }

        return $found;
    }

    /**
     * Each static property of a package class that holds one of the values, by
     * the path to it.
     *
     * @param  list<string>  $values
     * @return list<string>
     */
    protected function retainedByStatics(array $values): array
    {
        $found = [];
        $seen  = [];

        foreach (get_declared_classes() as $class) {

            if (!str_starts_with($class, 'SineMacula\Laravel\Sso\\')) {
                continue;
            }

            foreach ((new \ReflectionClass($class))->getStaticProperties() as $name => $value) {
                $this->walkRetained($value, "{$class}::\${$name}", $values, $seen, $found, 0);
            }
        }

        return $found;
    }

    /**
     * The handler of each signal the worker's loop takes over, by the signal:
     * none where the process has no signals to take over.
     *
     * @return array<int, callable|int>
     */
    private static function signalHandlers(): array
    {
        if (!function_exists('pcntl_signal_get_handler')) {
            return [];
        }

        $handlers = [];

        foreach ([SIGQUIT, SIGTERM, SIGINT, SIGUSR2, SIGCONT, SIGALRM] as $signal) {
            $handlers[$signal] = pcntl_signal_get_handler($signal);
        }

        return $handlers;
    }

    /**
     * Put back the handlers, and whether signals were delivered at once.
     *
     * @param  array<int, callable|int>  $handlers
     * @param  bool  $async
     * @return void
     */
    private static function restoreSignalHandlers(array $handlers, bool $async): void
    {
        if ($handlers === []) {
            return;
        }

        foreach ($handlers as $signal => $handler) {
            pcntl_signal($signal, $handler);
        }

        pcntl_alarm(0);
        pcntl_async_signals($async);
    }

    /**
     * Follow the value, recording each string that carries one of the values:
     * through arrays and package objects only, since the framework's own
     * objects hold the application's configuration and the like.
     *
     * @param  mixed  $value
     * @param  string  $path
     * @param  list<string>  $values
     * @param  array<int, true>  $seen
     * @param  list<string>  $found
     * @param  int  $depth
     * @return void
     */
    private function walkRetained(mixed $value, string $path, array $values, array &$seen, array &$found, int $depth): void
    {
        if ($depth > 12) {
            return;
        }

        if (is_string($value)) {
            $carried = array_filter($values, static fn (string $needle): bool => str_contains($value, $needle));
            $found   = [...$found, ...array_fill(0, count($carried), $path)];

            return;
        }

        foreach (self::childrenOf($value, $seen) as $key => $child) {
            $this->walkRetained($child, is_array($value) ? "{$path}[{$key}]" : "{$path}->{$key}", $values, $seen, $found, $depth + 1);
        }
    }

    /**
     * What the walk follows from the value: an array's items, what a
     * `\SensitiveParameterValue` hides, or the properties of a package object
     * not yet seen.
     *
     * @param  mixed  $value
     * @param  array<int, true>  $seen
     * @return array<array-key, mixed>
     */
    private static function childrenOf(mixed $value, array &$seen): array
    {
        if (is_array($value)) {
            return $value;
        }

        if ($value instanceof \SensitiveParameterValue) {
            return ['value' => $value->getValue()];
        }

        if (!is_object($value) || !str_starts_with($value::class, 'SineMacula\Laravel\Sso\\') || isset($seen[spl_object_id($value)])) {
            return [];
        }

        $seen[spl_object_id($value)] = true;

        return self::propertiesOf($value);
    }

    /**
     * The initialised instance properties of the object, its parents' included.
     *
     * @param  object  $object
     * @return array<string, mixed>
     */
    private static function propertiesOf(object $object): array
    {
        $properties = [];

        for ($class = new \ReflectionObject($object); $class !== false; $class = $class->getParentClass()) {

            $held = array_filter($class->getProperties(), static fn (\ReflectionProperty $property): bool => !$property->isStatic() && $property->isInitialized($object));

            foreach ($held as $property) {
                $properties[$property->getName()] = $property->getValue($object);
            }
        }

        return $properties;
    }

    /**
     * Hand the services Octane gave the request's sandbox back to the root
     * application: the sandbox they hold has been flushed once the worker is
     * done with it. Only the application they hold is replaced, as the next
     * request's own listeners replace it again; nothing is reset, so whatever
     * the next request does not see is down to Octane's lifecycle alone.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  \Symfony\Component\HttpFoundation\Response  $response
     * @return void
     */
    private function restoreRootApplication(Request $request, Response $response): void
    {
        $app   = $this->longLivedApplication();
        $event = new RequestTerminated($app, $app, $request, $response);

        foreach (Octane::prepareApplicationForNextOperation() as $listener) {

            if (!str_contains($listener, 'GiveNewApplicationInstanceTo')) {
                continue;
            }

            $app->make($listener)->handle($event);
        }
    }

    /**
     * The test's booted application.
     *
     * @return \Illuminate\Foundation\Application
     */
    private function longLivedApplication(): Application
    {
        $app = $this->app;

        self::assertInstanceOf(Application::class, $app);

        return $app;
    }
}
