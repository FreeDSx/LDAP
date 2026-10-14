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

namespace FreeDSx\Ldap\Server\Backend\Write\Schema;

use FreeDSx\Ldap\Schema\Validation\RuleViolation;

/**
 * A single schema violation detected by the validator.
 */
final readonly class SchemaViolation
{
    public function __construct(
        public RuleViolation $violation,
        public SchemaViolationDisposition $disposition,
    ) {}
}
