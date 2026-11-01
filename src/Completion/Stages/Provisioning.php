<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Sso\Completion\Stages;

/**
 * The `provisioning` step (SSO-8.6): where an unlinked `sign_in` result holding
 * no reservation will be offered, synchronously, to the unlinked-result event's
 * listeners with a single-use provisioning grant, and its link resolved again.
 *
 * Provisioning is not built yet, so the step offers nothing and passes every
 * result on unchanged; an unlinked `sign_in` result then ends at the unlinked
 * step.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final readonly class Provisioning extends UnbuiltStage {}
