<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

/**
 * The `domain_reservation` step (SSO-8.8): where linking by a verified domain
 * will reserve a link for an unlinked `sign_in` result, atomically under the
 * link store's uniqueness and limit, bound to the request, its handoff, the
 * identity matched and the linking email.
 *
 * Linking by a verified domain is not built yet, so the step reserves nothing
 * and passes every result on unchanged; an unlinked `sign_in` result then
 * reaches the provisioning and unlinked steps holding no reservation.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class DomainReservation extends UnbuiltStage {}
