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

use FreeDSx\Ldap\Schema\Validation\SchemaRule;

/**
 * An entry breaking one schema rule.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaViolationException extends OperationException
{
    public function __construct(
        string $message,
        int $code,
        public readonly SchemaRule $rule,
    ) {
        parent::__construct(
            $message,
            $code,
        );
    }
}
