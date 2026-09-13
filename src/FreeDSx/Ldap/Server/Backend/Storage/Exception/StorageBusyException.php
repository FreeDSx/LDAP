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
use Throwable;

/**
 * Thrown when a write keeps conflicting with concurrent writes after every retry the storage allows.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class StorageBusyException extends RuntimeException implements AnswerableExceptionInterface
{
    private const DIAGNOSTIC = 'The backend storage is too busy to complete the operation.';

    public function __construct(
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message,
            ResultCode::BUSY,
            $previous,
        );
    }

    public function getDiagnostic(): string
    {
        return self::DIAGNOSTIC;
    }
}
