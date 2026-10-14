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
 * Request-scoped record of schema violations detected during a write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaViolations
{
    /**
     * @var SchemaViolation[]
     */
    private array $violations = [];

    public function record(
        RuleViolation $violation,
        SchemaViolationDisposition $disposition,
    ): void {
        $this->violations[] = new SchemaViolation(
            $violation,
            $disposition,
        );
    }

    /**
     * @return SchemaViolation[]
     */
    public function all(): array
    {
        return $this->violations;
    }
}
