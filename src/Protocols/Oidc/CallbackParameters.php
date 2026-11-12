<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

/**
 * An OpenID Connect callback's parameters, read from the raw query because
 * PHP's parser keeps the last duplicate, builds arrays and folds names.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackParameters implements \JsonSerializable
{
    /** @var array<string, int> The parameters kept, as keys; others are checked, then dropped. */
    private const array READ = ['code' => 0, 'state' => 1, 'iss' => 2, 'error' => 3];

    /** @var string A control character: C0, DEL or C1. */
    private const string CONTROL = '/\p{Cc}/u';

    /** @var \SensitiveParameterValue The parameters the callback reads, by name. */
    private \SensitiveParameterValue $values;

    /**
     * Constructor.
     *
     * @param  array<array-key, string>  $values
     */
    private function __construct(

        // Not promoted: held wrapped
        #[\SensitiveParameter]
        array $values,
    ) {
        $this->values = new \SensitiveParameterValue($values);
    }

    /**
     * Show each parameter's name, never a value.
     *
     * @return array<array-key, string>
     */
    public function __debugInfo(): array
    {
        return array_map(static fn (): string => '[redacted]', $this->all());
    }

    /**
     * Refuse to be serialised; the parameters live only for their request.
     *
     * @return array<string, mixed>
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     */
    public function __serialize(): array
    {
        throw new \LogicException('A callback\'s parameters cannot be serialised.');
    }

    /**
     * Refuse to be unserialised.
     *
     * @param  array<string, mixed>  $data
     * @return void
     *
     * @throws \LogicException
     *
     * @SuppressWarnings("php:S100")
     * @SuppressWarnings("php:S1172")
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A callback\'s parameters cannot be unserialised.');
    }

    /**
     * Encode the same redacted view as a dump.
     *
     * @return array<array-key, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * Parse the raw query, or return `null` when it is empty, over a cap, or
     * any parameter repeats or is refused.
     *
     * @param  string  $rawQuery
     * @param  \SineMacula\Laravel\Sso\Protocols\Oidc\OidcLimits  $limits
     * @return ?self
     *
     * @throws \InvalidArgumentException
     */
    public static function parse(#[\SensitiveParameter] string $rawQuery, OidcLimits $limits): ?self
    {
        if (strlen($rawQuery) > $limits->maxCallbackQueryBytes()) {
            return null;
        }

        $segments = array_filter(explode('&', $rawQuery), static fn (string $segment): bool => $segment !== '');
        $count    = count($segments);
        $pairs    = $count === 0 || $count > $limits->maxCallbackParameters() ? null : self::pairs($segments, $limits->maxCallbackParameterBytes());

        return $pairs === null ? null : new self(array_intersect_key($pairs, self::READ));
    }

    /**
     * The authorisation code, for the token request only.
     *
     * @return ?string
     */
    public function code(): ?string
    {
        return $this->all()['code'] ?? null;
    }

    /**
     * The protocol state, for correlation only.
     *
     * @return ?string
     */
    public function state(): ?string
    {
        return $this->all()['state'] ?? null;
    }

    /**
     * The RFC 9207 issuer.
     *
     * @return ?string
     */
    public function iss(): ?string
    {
        return $this->all()['iss'] ?? null;
    }

    /**
     * The provider's error code.
     *
     * @return ?string
     */
    public function error(): ?string
    {
        return $this->all()['error'] ?? null;
    }

    /**
     * The parameters the callback reads, by name.
     *
     * @return array<array-key, string>
     */
    private function all(): array
    {
        /** @var array<array-key, string> */
        return $this->values->getValue();
    }

    /**
     * Each segment's form-decoded name and value, or `null` when a decoded name
     * repeats or a pair is refused.
     *
     * @param  array<int, string>  $segments
     * @param  int  $maxBytes
     * @return ?array<array-key, string>
     */
    private static function pairs(#[\SensitiveParameter] array $segments, int $maxBytes): ?array
    {
        $pairs = [];

        foreach ($segments as $segment) {

            [$name, $value] = explode('=', $segment, 2) + [1 => ''];

            $name  = urldecode($name);
            $value = urldecode($value);

            if (array_key_exists($name, $pairs) || !self::isAcceptable($name, $value, $maxBytes)) {
                return null;
            }

            $pairs[$name] = $value;
        }

        return $pairs;
    }

    /**
     * Whether the name is not array-shaped and both sides are capped text.
     *
     * @param  string  $name
     * @param  string  $value
     * @param  int  $maxBytes
     * @return bool
     */
    private static function isAcceptable(string $name, #[\SensitiveParameter] string $value, int $maxBytes): bool
    {
        $flat    = strpbrk($name, '[]') === false;
        $bounded = max(strlen($name), strlen($value)) <= $maxBytes;

        return $flat && $bounded && self::isText($name) && self::isText($value);
    }

    /**
     * Whether the text is valid UTF-8 with no control character.
     *
     * @param  string  $text
     * @return bool
     */
    private static function isText(#[\SensitiveParameter] string $text): bool
    {
        return mb_check_encoding($text, 'UTF-8') && preg_match(self::CONTROL, $text) === 0;
    }
}
