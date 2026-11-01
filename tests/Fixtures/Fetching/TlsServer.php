<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Fetching;

use GuzzleHttp\Psr7\Stream;
use Psr\Http\Message\StreamInterface;

/**
 * A one-connection HTTPS server on 127.0.0.1 for the package's own tests, run
 * in a PHP process of its own, with a self-signed certificate for the name a
 * test gives, written to a temporary directory.
 *
 * It accepts one connection, reads the request's head, and answers a request it
 * read as its mode says: `ok` with a two-byte body of a declared length, or
 * `stream` with a chunked body of no declared length, far larger than any size
 * cap, written until the client stops reading or it is all sent. It then
 * reports, on one line of its output, whether its side of the TLS handshake
 * completed, the request line and `Host` header it read (`null` when the client
 * sent none), the body bytes it sent and whether it sent them all.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class TlsServer
{
    /** @var int The body bytes the `stream` mode offers: 64 MiB. */
    public const int STREAMED_BYTES = 67108864;

    /** @var int The bytes of each chunk the `stream` mode writes. */
    private const int CHUNK_BYTES = 16384;

    /** @var int The seconds the server waits for the connection, or for a read. */
    private const int TIMEOUT_SECONDS = 10;

    /** @var string What the server runs in its own process. */
    private const string SERVE = 'require $argv[1]; \Tests\Fixtures\Fetching\TlsServer::serve($argv[2], $argv[3], $argv[4]);';

    /** @var string The head of the `ok` mode's answer. */
    private const string OK_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n";

    /** @var string The head of the `stream` mode's answer. */
    private const string STREAM_HEAD = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";

    /**
     * Constructor.
     *
     * @param  string  $directory
     * @param  mixed  $process
     * @param  \Psr\Http\Message\StreamInterface  $output
     * @param  int  $port
     */
    private function __construct(

        /** The temporary directory the certificate, its key and the configuration are in. */
        private string $directory,

        /** The server's process, as `proc_open()` answered it. */
        private mixed $process,

        /** The pipe the server reports on. */
        private StreamInterface $output,

        /** The port the server listens on. */
        private int $port,
    ) {}

    /**
     * Start a server answering as the mode says, with a self-signed certificate
     * for the name.
     *
     * @param  'ok'|'stream'  $mode
     * @param  string  $name
     * @return self
     *
     * @throws \Random\RandomException
     * @throws \RuntimeException
     */
    public static function start(string $mode, string $name): self
    {
        $directory = sys_get_temp_dir() . '/sso-tls-' . bin2hex(random_bytes(8));

        mkdir($directory);

        self::writeCertificate($directory, $name);

        return self::launch($directory, $mode);
    }

    /**
     * In the server's own process: listen, report the port, serve one
     * connection as the mode says, and report what happened.
     *
     * @param  string  $certificate
     * @param  string  $key
     * @param  string  $mode
     * @return void
     */
    public static function serve(string $certificate, string $key, string $mode): void
    {
        $context = stream_context_create(['ssl' => ['local_cert' => $certificate, 'local_pk' => $key, 'verify_peer' => false]]);
        $server  = stream_socket_server('tls://127.0.0.1:0', $code, $message, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
        $address = $server === false ? ':0' : (string) stream_socket_get_name($server, false);

        fwrite(STDOUT, substr($address, (int) strrpos($address, ':') + 1) . "\n");
        fflush(STDOUT);

        $accepted = $server === false ? false : @stream_socket_accept($server, self::TIMEOUT_SECONDS);

        if ($accepted === false) {
            self::report(['handshake' => false, 'request' => null, 'host' => null, 'sent' => 0, 'complete' => false]);

            return;
        }

        stream_set_timeout($accepted, self::TIMEOUT_SECONDS);

        $connection        = new Stream($accepted);
        [$request, $host]  = self::readHead($connection);
        [$sent, $complete] = match (true) {
            $request === null     => [0, false],
            $mode    === 'stream' => self::stream($connection),
            default               => [2, self::write($connection, self::OK_HEAD . 'ok')],
        };

        $connection->close();

        self::report(['handshake' => true, 'request' => $request, 'host' => $host, 'sent' => $sent, 'complete' => $complete]);
    }

    /**
     * The port the server listens on.
     *
     * @return int
     */
    public function port(): int
    {
        return $this->port;
    }

    /**
     * The certificate, which a client that trusts it uses as its CA file.
     *
     * @return string
     */
    public function certificate(): string
    {
        return $this->directory . '/certificate.pem';
    }

    /**
     * Wait for the server to finish and answer its report, then remove its
     * process and files.
     *
     * @return array{handshake: bool, request: ?string, host: ?string, sent: int, complete: bool}
     *
     * @throws \JsonException
     * @throws \RuntimeException
     */
    public function finish(): array
    {
        $line = self::readLine($this->output);

        $this->output->close();

        if (is_resource($this->process)) {
            proc_close($this->process);
        }

        foreach (glob($this->directory . '/*') ?: [] as $file) {
            unlink($file);
        }

        rmdir($this->directory);

        /** @var array{handshake: bool, request: ?string, host: ?string, sent: int, complete: bool} */
        return json_decode($line, true, 4, JSON_THROW_ON_ERROR);
    }

    /**
     * Run the server in a PHP process of its own, with the certificate and key
     * in the directory, and read the port it listens on.
     *
     * @param  string  $directory
     * @param  string  $mode
     * @return self
     *
     * @throws \RuntimeException
     */
    private static function launch(string $directory, string $mode): self
    {
        $command = [PHP_BINARY, '-d', 'xdebug.mode=off', '-d', 'display_errors=0', '-d', 'log_errors=0', '-r', self::SERVE, '--'];
        $files   = [dirname(__DIR__, 3) . '/vendor/autoload.php', $directory . '/certificate.pem', $directory . '/key.pem'];
        $process = proc_open([...$command, ...$files, $mode], [0 => ['pipe', 'r'], 1 => ['pipe', 'w']], $pipes);

        if (!is_resource($process)) {
            throw new \RuntimeException('The test server could not be started.');
        }

        fclose($pipes[0]);
        stream_set_timeout($pipes[1], self::TIMEOUT_SECONDS * 2);

        $output = new Stream($pipes[1]);
        $port   = (int) self::readLine($output);

        if ($port === 0) {
            throw new \RuntimeException('The test server did not start listening.');
        }

        return new self($directory, $process, $output, $port);
    }

    /**
     * Write a self-signed certificate for the name, valid for a day, and its
     * key, into the directory.
     *
     * @param  string  $directory
     * @param  string  $name
     * @return void
     *
     * @throws \RuntimeException
     */
    private static function writeCertificate(string $directory, string $name): void
    {
        $configuration = $directory . '/openssl.cnf';

        file_put_contents($configuration, implode("\n", [
            '[req]',
            'distinguished_name = name',
            '[name]',
            '[server]',
            'basicConstraints = critical, CA:TRUE',
            'keyUsage = critical, digitalSignature, keyCertSign',
            'extendedKeyUsage = serverAuth',
            'subjectAltName = DNS:' . $name,
            '',
        ]));

        $options = ['config' => $configuration, 'digest_alg' => 'sha256', 'x509_extensions' => 'server'];
        $key     = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);

        if ($key === false) {
            throw new \RuntimeException('The test key could not be made: ' . openssl_error_string());
        }

        $request = openssl_csr_new(['commonName' => $name], $key, $options);
        $signed  = is_bool($request) ? false : openssl_csr_sign($request, null, $key, 1, $options, time());

        if ($signed === false || !openssl_x509_export_to_file($signed, $directory . '/certificate.pem') || !openssl_pkey_export_to_file($key, $directory . '/key.pem')) {
            throw new \RuntimeException('The test certificate could not be made: ' . openssl_error_string());
        }

        // Leave nothing in OpenSSL's error queue for a later test to find.
        do {
            $error = openssl_error_string();
        } while ($error !== false);
    }

    /**
     * Read the request's head, and answer its request line and `Host` header;
     * both `null` when the client sent no request.
     *
     * @param  \Psr\Http\Message\StreamInterface  $connection
     * @return array{0: ?string, 1: ?string}
     */
    private static function readHead(StreamInterface $connection): array
    {
        $lines = [];

        try {
            while (($line = rtrim(self::readLine($connection))) !== '') {
                $lines[] = $line;
            }
        } catch (\RuntimeException) {
            return [null, null];
        }

        $host = null;

        foreach ($lines as $line) {
            $host = stripos($line, 'host:') === 0 ? trim(substr($line, 5)) : $host;
        }

        return [$lines[0] ?? null, $host];
    }

    /**
     * Read one line, up to and including its newline, or up to the end or a
     * read that times out.
     *
     * @param  \Psr\Http\Message\StreamInterface  $stream
     * @return string
     *
     * @throws \RuntimeException
     */
    private static function readLine(StreamInterface $stream): string
    {
        $line = '';

        while (!str_ends_with($line, "\n") && !$stream->eof()) {
            $byte = $stream->read(1);

            if ($byte === '') {
                break;
            }

            $line .= $byte;
        }

        return $line;
    }

    /**
     * Answer with a chunked body of no declared length, chunk by chunk, until
     * the client stops reading or it is all sent.
     *
     * @param  \Psr\Http\Message\StreamInterface  $connection
     * @return array{0: int, 1: bool}
     */
    private static function stream(StreamInterface $connection): array
    {
        if (!self::write($connection, self::STREAM_HEAD)) {
            return [0, false];
        }

        $chunk = dechex(self::CHUNK_BYTES) . "\r\n" . str_repeat('a', self::CHUNK_BYTES) . "\r\n";
        $sent  = 0;

        while ($sent < self::STREAMED_BYTES) {
            if (!self::write($connection, $chunk)) {
                return [$sent, false];
            }

            $sent += self::CHUNK_BYTES;
        }

        return [$sent, self::write($connection, "0\r\n\r\n")];
    }

    /**
     * Write all the bytes, however many writes it takes; `false` once a write
     * fails or writes nothing, as it does once the client has gone.
     *
     * @param  \Psr\Http\Message\StreamInterface  $connection
     * @param  string  $bytes
     * @return bool
     */
    private static function write(StreamInterface $connection, string $bytes): bool
    {
        try {
            while ($bytes !== '') {
                $written = $connection->write($bytes);

                if ($written === 0) {
                    return false;
                }

                $bytes = substr($bytes, $written);
            }
        } catch (\RuntimeException) {
            return false;
        }

        return true;
    }

    /**
     * Write the report on one line of the output.
     *
     * @param  array{handshake: bool, request: ?string, host: ?string, sent: int, complete: bool}  $report
     * @return void
     *
     * @throws \JsonException
     */
    private static function report(array $report): void
    {
        fwrite(STDOUT, json_encode($report, JSON_THROW_ON_ERROR) . "\n");
    }
}
