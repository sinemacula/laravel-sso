<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Protocols\Oidc;

/**
 * The parameters of an OpenID Connect callback, read from its raw query before
 * anything has parsed it (SSO-7.1), since a parsed query hides what the
 * callback must refuse: PHP's parser keeps the last of two values, makes an
 * array of `state[]` and folds names.
 *
 * `parse()` splits the query on `&`, ignores empty segments, splits each pair
 * at its first `=` and form-decodes both sides (`+` is a space). The whole
 * query is refused, with `null`, when it is empty or longer than
 * `OidcLimits::maxCallbackQueryBytes()`, when it holds no parameter or more
 * than `OidcLimits::maxCallbackParameters()`, or when any parameter:
 *
 * - repeats a name once decoded, compared exactly, so `st%61te` repeats `state`
 *   and `State` does not;
 * - has a name holding `[` or `]`, the shape of an array;
 * - has a decoded name or value longer than
 *   `OidcLimits::maxCallbackParameterBytes()`;
 * - has a decoded name or value that is not valid UTF-8 or holds a control
 *   character.
 *
 * A name the callback does not read is ignored once it has passed these, so it
 * still counts towards the caps and may not repeat; it is not kept.
 *
 * What it keeps is attacker-supplied, and holds an authorisation code and the
 * protocol state, so the values are held in a `\SensitiveParameterValue`, given
 * only through their accessors: a dump and JSON encoding show the names of what
 * arrived and no value, and it refuses to be serialised or unserialised
 * (SSO-7.6, SSO-9.8). It holds nothing between calls (SSO-11.2).
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class CallbackParameters implements \JsonSerializable
{
    /** @var array<string, int> The parameters the callback reads, as keys; every other name is ignored. */
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

        // The parameters the callback reads, by name; held wrapped
        #[\SensitiveParameter]
        array $values,
    ) {
        $this->values = new \SensitiveParameterValue($values);
    }

    /**
     * What a dump shows: the name of each parameter given, never a value.
     *
     * @return array<array-key, string>
     */
    public function __debugInfo(): array
    {
        return array_map(static fn (): string => '[redacted]', $this->all());
    }

    /**
     * Refuse to be serialised: a callback's parameters are read in the request
     * they arrived in and kept nowhere.
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
     * What JSON encoding shows: the same as a dump, never a value.
     *
     * @return array<array-key, string>
     */
    #[\Override]
    public function jsonSerialize(): array
    {
        return $this->__debugInfo();
    }

    /**
     * The parameters of the raw query, or `null` when it is refused.
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
     * The authorisation code, for the token request and nothing else.
     *
     * @return ?string
     */
    public function code(): ?string
    {
        return $this->all()['code'] ?? null;
    }

    /**
     * The protocol state, for the correlation and nothing else.
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
     * Each segment's decoded name and value, or `null` when one repeats a name
     * or is refused.
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
     * Whether the decoded name is not array-shaped, and the name and value are
     * within the cap and are text.
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
