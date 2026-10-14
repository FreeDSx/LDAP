<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Schema\Validation;

/**
 * A write breaking one schema rule, with the result code and message a client is answered with.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RuleViolation
{
    public function __construct(
        public SchemaRule $rule,
        public int $code,
        public string $message,
    ) {}
}
