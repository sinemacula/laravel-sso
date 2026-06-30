<?php

use SineMacula\CodingStandards\PhpCsFixerConfig;

return PhpCsFixerConfig::make([
    dirname(__DIR__, 2) . '/src',
    dirname(__DIR__, 2) . '/config',
    dirname(__DIR__, 2) . '/benchmarks',
    dirname(__DIR__, 2) . '/database',
    dirname(__DIR__, 2) . '/tests',
], [
    'php_unit_test_class_requires_covers' => false,
]);
