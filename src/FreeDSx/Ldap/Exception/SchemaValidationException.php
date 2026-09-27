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

/**
 * Every schema rule an entry breaks, answered with the result code and message of the first.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaValidationException extends OperationException
{
    /**
     * @param non-empty-list<SchemaViolationException> $violations
     */
    public function __construct(public readonly array $violations)
    {
        parent::__construct(
            $violations[0]->getMessage(),
            $violations[0]->getCode(),
            $violations[0],
        );
    }
}
