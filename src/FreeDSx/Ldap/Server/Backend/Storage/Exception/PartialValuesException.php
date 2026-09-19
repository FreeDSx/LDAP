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

namespace FreeDSx\Ldap\Server\Backend\Storage\Exception;

use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Thrown when an entry carrying only a range of a linked attribute's values is written back, which would drop the rest.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PartialValuesException extends RuntimeException implements AnswerableExceptionInterface
{
    public function __construct(string $attribute)
    {
        parent::__construct(
            sprintf(
                'The attribute "%s" holds a range of its values and cannot be stored.',
                $attribute,
            ),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    public function getDiagnostic(): string
    {
        return $this->getMessage();
    }
}
