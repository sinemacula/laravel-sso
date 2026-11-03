<?php

declare(strict_types = 1);

namespace Tests\Unit\Events;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Sso\Contracts\SsoEvent;
use SineMacula\Laravel\Sso\Events\EventContext;
use SineMacula\Laravel\Sso\Events\ResultUnlinked;
use SineMacula\Laravel\Sso\Provisioning\ProvisioningGrant;
use SineMacula\Laravel\Sso\Results\VerifiedResult;

/**
 * One scan of every package event, with one list of what no event may carry
 * (SSO-10.4): every class under `Events` that is a `Contracts\SsoEvent` is
 * found, none is left out, and no public property of any of them, or of the
 * context each carries, is named as a secret, a verifier, a handoff code,
 * protocol state, a nonce, an assertion, a token, a subject, an email, an
 * attribute, a payload or a header, unless it is an enum, which carries none;
 * and only `ResultUnlinked` carries the verified result, through its grant.
 *
 * The family tests (`FlowEventClassesTest` and the others) pin each event's
 * exact properties; this scan holds every event, those families included, to
 * the one list, so an event added later is held to it without being named.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(EventContext::class)]
#[CoversClass(ResultUnlinked::class)]
final class EveryEventClassTest extends TestCase
{
    /** @var list<string> What no property name may contain, compared without case or underscores. */
    private const array FORBIDDEN_PARTS = [
        'secret', 'verifier', 'handoffcode', 'nonce', 'relaystate', 'assertion', 'token', 'password', 'privatekey',
        'subject', 'nameid', 'sessionindex', 'email', 'attribute', 'payload', 'header', 'rawcontext', 'samlresponse',
        'authorizationcode',
    ];

    /** @var list<string> What no property may be named, compared without case or underscores. */
    private const array FORBIDDEN_NAMES = ['code', 'state', 'result', 'grant', 'claims'];

    /** @var list<class-string> The types that carry the verified result. */
    private const array RESULT_TYPES = [VerifiedResult::class, ProvisioningGrant::class];

    /** @var list<string> Every package event, by its short name. */
    private const array EVENTS = [
        'AuthorizationRequestStarted', 'ConnectionCreated', 'ConnectionDeleted', 'ConnectionDisabled', 'ConnectionEnabled',
        'ConnectionUpdated', 'DomainClaimed', 'DomainLapsed', 'DomainRecheckFailed', 'DomainRemoved', 'DomainRestored',
        'DomainVerified', 'EnforcementChanged', 'ExemptionUsed', 'FlowFailed', 'HandoffIssued', 'HandoffRedeemed',
        'JwksRefreshFailed', 'JwksRefreshed', 'KeyAdded', 'KeyMadeCurrent', 'KeyNearingExpiry', 'KeyRetired',
        'LinkActivated', 'LinkConfirmed', 'LinkCreated', 'LinkRemoved', 'LinkSuspended', 'MetadataRefreshFailed',
        'MetadataRefreshed', 'ReauthenticationCompleted', 'ResultUnlinked', 'ResultVerified', 'UnsolicitedResponseReinitiated',
    ];

    /**
     * The scan finds every package event, and nothing else.
     *
     * @return void
     */
    public function testFindsEveryPackageEvent(): void
    {
        self::assertSame(self::EVENTS, array_map(static fn (string $event): string => (new \ReflectionClass($event))->getShortName(), self::events()));
    }

    /**
     * Rows of `[event]`: every class under `Events` that is a package event.
     *
     * @return iterable<string, array{0: class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>}>
     */
    public static function provideEvents(): iterable
    {
        foreach (self::events() as $event) {
            yield (new \ReflectionClass($event))->getShortName() => [$event];
        }
    }

    /**
     * No property of the event, or of its context, is named as something an
     * event must never carry, unless it is an enum.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>  $event
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testCarriesNothingThatMustNotLeave(string $event): void
    {
        $offending = [];

        foreach ([$event, EventContext::class] as $class) {
            foreach (self::properties($class) as $property) {

                if (self::isResultCarrier($event, $property) || !self::isForbidden($property)) {
                    continue;
                }

                $offending[] = "{$class}::\${$property->getName()}";
            }
        }

        self::assertSame([], $offending);
    }

    /**
     * Only `ResultUnlinked` carries the verified result, and only through its
     * grant: no other event has a property of a type that holds it.
     *
     * @param  class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>  $event
     * @return void
     */
    #[DataProvider('provideEvents')]
    public function testOnlyTheUnlinkedResultCarriesTheResult(string $event): void
    {
        $carriers = array_values(array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            array_filter(self::properties($event), static fn (\ReflectionProperty $property): bool => self::holdsTheResult($property)),
        ));

        self::assertSame($event === ResultUnlinked::class ? ['grant'] : [], $carriers);
    }

    /**
     * The name checks catch a forbidden part anywhere in a name and a forbidden
     * name exactly, without case or underscores, and pass over an enum so named
     * and a name that only contains a forbidden name.
     *
     * @return void
     */
    public function testTheNameCheckTellsAForbiddenNameFromAnother(): void
    {
        $probe = new class {
            /** @var string A token, by a part of its name. */
            public string $access_token = '';

            /** @var string Protocol state, by a part of its name. */
            public string $relayState = '';

            /** @var string A code, by its name in another case. */
            public string $Code = '';

            /** @var string An authorisation code, by a part of its name. */
            public string $authorization_code = '';

            /** @var string An email, by a part of its name. */
            public string $emailAddress = '';

            /** @var ?\UnitEnum A state that is an enum, which carries nothing. */
            public ?\UnitEnum $state = null;

            /** @var string A name that only contains a forbidden name. */
            public string $connectionCode2 = '';

            /** @var string A name that says nothing forbidden. */
            public string $domainId = '';
        };

        $flagged = array_map(
            static fn (\ReflectionProperty $property): string => $property->getName(),
            array_values(array_filter(self::properties($probe::class), static fn (\ReflectionProperty $property): bool => self::isForbidden($property))),
        );

        self::assertSame(['access_token', 'relayState', 'Code', 'authorization_code', 'emailAddress'], $flagged);
    }

    /**
     * Every class under `Events` that is a package event, by short name.
     *
     * @return list<class-string<\SineMacula\Laravel\Sso\Contracts\SsoEvent>>
     */
    private static function events(): array
    {
        $events = [];

        foreach (glob(dirname(__DIR__, 3) . '/src/Events/*.php') ?: [] as $file) {

            $class = 'SineMacula\Laravel\Sso\Events\\' . basename($file, '.php');

            if (!class_exists($class) || !is_subclass_of($class, SsoEvent::class)) {
                continue;
            }

            $events[] = $class;
        }

        sort($events);

        return $events;
    }

    /**
     * The public properties the class declares, its promoted ones included.
     *
     * @param  class-string  $class
     * @return list<\ReflectionProperty>
     */
    private static function properties(string $class): array
    {
        return (new \ReflectionClass($class))->getProperties(\ReflectionProperty::IS_PUBLIC);
    }

    /**
     * Whether the property is named as something an event must never carry and
     * is not an enum.
     *
     * @param  \ReflectionProperty  $property
     * @return bool
     */
    private static function isForbidden(\ReflectionProperty $property): bool
    {
        $name = strtolower(str_replace('_', '', $property->getName()));
        $type = $property->getType();

        if ($type instanceof \ReflectionNamedType && !$type->isBuiltin() && is_a($type->getName(), \UnitEnum::class, true)) {
            return false;
        }

        foreach (self::FORBIDDEN_PARTS as $part) {
            if (str_contains($name, $part)) {
                return true;
            }
        }

        return in_array($name, self::FORBIDDEN_NAMES, true);
    }

    /**
     * Whether the property is the one through which the unlinked event carries
     * the result.
     *
     * @param  class-string  $event
     * @param  \ReflectionProperty  $property
     * @return bool
     */
    private static function isResultCarrier(string $event, \ReflectionProperty $property): bool
    {
        return $event === ResultUnlinked::class && $property->getName() === 'grant' && self::holdsTheResult($property);
    }

    /**
     * Whether the property's type holds the verified result.
     *
     * @param  \ReflectionProperty  $property
     * @return bool
     */
    private static function holdsTheResult(\ReflectionProperty $property): bool
    {
        $type = $property->getType();

        return $type instanceof \ReflectionNamedType && in_array(ltrim($type->getName(), '?'), self::RESULT_TYPES, true);
    }
}
