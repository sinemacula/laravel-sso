<?php

declare(strict_types = 1);

namespace Tests\Integration\Logging;

use PHPUnit\Framework\Attributes\CoversClass;
use SineMacula\Laravel\Sso\Events\Enums\FailureReason;
use SineMacula\Laravel\Sso\Logging\DiagnosticSanitizer;
use SineMacula\Laravel\Sso\Logging\Redactor;
use SineMacula\Laravel\Sso\Logging\SanitizingLogger;
use SineMacula\Laravel\Sso\Secrets\Secret;
use Tests\Concerns\CapturesLogs;
use Tests\TestCase;

/**
 * Integration tests, through the container's logger and a real channel, that no
 * verifier, handoff code, protocol state, assertion, provider token or secret
 * reaches a log, while the public reference and the reason code do (SSO-5.7,
 * SSO-9.8, SSO-11.9).
 *
 * Each test logs what a failing flow would: an OIDC token endpoint's error
 * body, a SAML status message, the callback URL, the token request, and an
 * exception. This is the template each flow's own test follows: run the flow
 * with `CapturesLogs`, then assert with `assertNothingLoggedContains()` that
 * none of its secrets appear and with `assertLoggedContains()` that its
 * reference and reason do.
 *
 * Every secret is built at run time, so no secret scanner takes a fixture for a
 * real credential.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(SanitizingLogger::class)]
#[CoversClass(Redactor::class)]
#[CoversClass(DiagnosticSanitizer::class)]
final class NothingSecretIsLoggedTest extends TestCase
{
    use CapturesLogs;

    /** @var string The request's public reference, the only flow identifier a log may carry. */
    private const string REFERENCE = '01JBQ7Z3X9N4K2M8P5R6T0VWXY';

    /** @var string The provider's error code, which a log may carry. */
    private const string PROVIDER_ERROR = 'invalid_grant';

    /** @var string The provider's error description, which a log may carry once sanitised. */
    private const string DESCRIPTION = 'The authorization code has expired.';

    /** @var array<string, string> Every secret the flows below hold, by name. */
    private array $secrets = [];

    /**
     * Build the secrets and capture the package's logs.
     *
     * @return void
     *
     * @throws \Random\RandomException
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->secrets = [
            'access token'  => 'at-' . bin2hex(random_bytes(12)),
            'refresh token' => 'rt-' . bin2hex(random_bytes(12)),
            'ID token'      => implode('.', [self::base64url('{"alg":"RS256","kid":"k1"}'), self::base64url('{"sub":"248289761001","nonce":"n-0S6"}'), bin2hex(random_bytes(16))]),
            'code'          => 'ac-' . bin2hex(random_bytes(8)),
            'state'         => 'st-' . bin2hex(random_bytes(8)),
            'verifier'      => self::base64url(random_bytes(32)),
            'nonce'         => 'nc-' . bin2hex(random_bytes(8)),
            'handoff code'  => self::base64url(random_bytes(32)),
            'relay state'   => 'rs-' . bin2hex(random_bytes(8)),
            'subject'       => 'alice-' . bin2hex(random_bytes(4)) . '@example.com',
            'client secret' => 'cs-' . bin2hex(random_bytes(12)),
            'signature'     => base64_encode(random_bytes(64)),
            'saml response' => base64_encode(str_repeat('<samlp:Response ID="_r1">', 4)),
        ];

        $this->captureLogs();
    }

    /**
     * An OIDC token endpoint's error body that also carries tokens, logged as
     * the provider's diagnostic: its error code and description are kept, its
     * tokens are not.
     *
     * @return void
     */
    public function testAnOAuthErrorBodyKeepsNoToken(): void
    {
        $this->logOAuthErrorBody();

        $this->assertNothingSecretLogged();
        $this->assertLoggedContains(self::REFERENCE, FailureReason::PROVIDER_ERROR->value, self::PROVIDER_ERROR, self::DESCRIPTION, '"access_token":"[redacted]"');
    }

    /**
     * A SAML status message that echoes an assertion: the assertion is redacted
     * whole, its subject with it, and the status kept.
     *
     * @return void
     */
    public function testASamlStatusMessageKeepsNoAssertion(): void
    {
        $this->logSamlStatus();

        $this->assertNothingSecretLogged();
        $this->assertLoggedContains(self::REFERENCE, FailureReason::PROVIDER_ERROR->value, 'status:Responder', 'Rejected [redacted]');
    }

    /**
     * The callback URL, with its code and state in the query, logged as a
     * message and in the context: the URL is kept, the code and state not.
     *
     * @return void
     */
    public function testACallbackUrlKeepsNoCodeOrState(): void
    {
        $this->logCallbackUrl();

        $this->assertNothingSecretLogged();
        $this->assertLoggedContains(self::REFERENCE, 'https://api.example.com/auth/sso/connections/acme/callback?code=[redacted]&state=[redacted]&iss=https://idp.example.com');
    }

    /**
     * The token request a failed exchange was for: its form's code, verifier,
     * client secret and nonce, its authorisation header and a decrypted secret
     * are all redacted, and its grant type kept.
     *
     * @return void
     */
    public function testATokenRequestKeepsNoCredential(): void
    {
        $this->logTokenRequest();

        $this->assertNothingSecretLogged();
        $this->assertLoggedContains(self::REFERENCE, 'authorization_code', '[object ' . Secret::class . ']');
    }

    /**
     * An exception whose message holds a handoff code, logged as Laravel logs
     * one: reduced to its class, its sanitised message and its code, with no
     * trace and no previous exception.
     *
     * @return void
     */
    public function testAnExceptionKeepsNoHandoffCode(): void
    {
        $this->logException();

        $this->assertNothingSecretLogged();
        $this->assertNothingLoggedContains('timed out', 'Lookup of', __FILE__);
        $this->assertLoggedContains(self::REFERENCE, \RuntimeException::class, 'Redemption of handoff code [redacted] failed: state=[redacted]');
    }

    /**
     * All of the above in one request, as a flow would log them: five records,
     * and nothing secret in any of them.
     *
     * @return void
     */
    public function testNothingSecretAcrossAFlow(): void
    {
        $this->logOAuthErrorBody();
        $this->logSamlStatus();
        $this->logCallbackUrl();
        $this->logTokenRequest();
        $this->logException();

        self::assertCount(5, $this->capturedLogRecords());

        $this->assertNothingSecretLogged();
        $this->assertLoggedContains(self::REFERENCE, FailureReason::PROVIDER_ERROR->value);
    }

    /**
     * Log a token endpoint's error body that carries tokens.
     *
     * @return void
     */
    private function logOAuthErrorBody(): void
    {
        $body = json_encode([
            'error'             => self::PROVIDER_ERROR,
            'error_description' => self::DESCRIPTION,
            'access_token'      => $this->secrets['access token'],
            'refresh_token'     => $this->secrets['refresh token'],
            'id_token'          => $this->secrets['ID token'],
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);

        $this->logger()->warning('Token request refused: ' . $body, $this->failure(['diagnostic' => $body]));
    }

    /**
     * Log a SAML status message that echoes a signed assertion, with the
     * response and relay state it came in.
     *
     * @return void
     */
    private function logSamlStatus(): void
    {
        $status = sprintf(implode('', [
            '<samlp:Status>',
            '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>',
            '<samlp:StatusMessage>Rejected <saml:Assertion ID="_a1" Version="2.0">',
            '<saml:Subject><saml:NameID>%s</saml:NameID></saml:Subject>',
            '<ds:Signature><ds:SignatureValue>%s</ds:SignatureValue></ds:Signature>',
            '</saml:Assertion></samlp:StatusMessage>',
            '</samlp:Status>',
        ]), $this->secrets['subject'], $this->secrets['signature']);

        $this->logger()->error("SAML response refused:\n" . $status, $this->failure([
            'status'       => $status,
            'SAMLResponse' => $this->secrets['saml response'],
            'RelayState'   => $this->secrets['relay state'],
        ]));
    }

    /**
     * Log the callback URL, with its code and state.
     *
     * @return void
     */
    private function logCallbackUrl(): void
    {
        $url = sprintf('https://api.example.com/auth/sso/connections/acme/callback?code=%s&state=%s&iss=https://idp.example.com', $this->secrets['code'], $this->secrets['state']);

        $this->logger()->notice('Callback received at ' . $url, $this->failure(['url' => $url]));
    }

    /**
     * Log the token request a failed exchange was for.
     *
     * @return void
     */
    private function logTokenRequest(): void
    {
        $this->logger()->error('Token exchange failed.', $this->failure([
            'form' => [
                'grant_type'    => 'authorization_code',
                'code'          => $this->secrets['code'],
                'code_verifier' => $this->secrets['verifier'],
                'client_secret' => $this->secrets['client secret'],
                'nonce'         => $this->secrets['nonce'],
            ],
            'headers' => ['Authorization' => 'Basic ' . base64_encode('client:' . $this->secrets['client secret'])],
            'request' => ['secret' => new Secret($this->secrets['client secret']), 'held' => new Secret($this->secrets['client secret'])],
        ]));
    }

    /**
     * Log an exception whose message, and whose previous exception's, holds a
     * handoff code.
     *
     * @return void
     */
    private function logException(): void
    {
        $previous  = new \RuntimeException('Lookup of ' . $this->secrets['handoff code'] . ' timed out.');
        $exception = new \RuntimeException("Redemption of handoff code {$this->secrets['handoff code']} failed:\nstate={$this->secrets['state']}", 0, $previous);

        $this->logger()->critical('Redemption failed: ' . $exception->getMessage(), $this->failure(['exception' => $exception]));
    }

    /**
     * The context every failure carries: the public reference and the reason
     * code, then what the failure adds.
     *
     * @param  array<string, mixed>  $context
     * @return array<string, mixed>
     */
    private function failure(array $context): array
    {
        return ['request_reference' => self::REFERENCE, 'reason' => FailureReason::PROVIDER_ERROR, ...$context];
    }

    /**
     * Assert that none of the secrets, nor the parts of a token, were logged.
     *
     * @return void
     */
    private function assertNothingSecretLogged(): void
    {
        $this->assertNothingLoggedContains(...array_values($this->secrets), ...explode('.', $this->secrets['ID token']));
    }

    /**
     * The logger, as the container builds it.
     *
     * @return \SineMacula\Laravel\Sso\Logging\SanitizingLogger
     */
    private function logger(): SanitizingLogger
    {
        return app(SanitizingLogger::class);
    }

    /**
     * The bytes, base64url-encoded without padding.
     *
     * @param  string  $bytes
     * @return string
     */
    private static function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
