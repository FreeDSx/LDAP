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

namespace FreeDSx\Ldap\Exception;

use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;

/**
 * A rejected schema violation that carries the violations collected during the write so they can be audited.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaRuleException extends OperationException
{
    public function __construct(
        OperationException $violation,
        private readonly SchemaViolations $violations,
    ) {
        parent::__construct(
            $violation->getMessage(),
            $violation->getCode(),
            $violation,
            $violation->getMatchedDn(),
            $violation->controls(),
        );
    }

    public function getViolations(): SchemaViolations
    {
        return $this->violations;
    }
}
