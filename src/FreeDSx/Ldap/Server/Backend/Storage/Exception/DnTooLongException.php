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
 * Thrown when attempting to store an entry whose DN exceeds the storage backend's supported maximum length.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class DnTooLongException extends RuntimeException implements AnswerableExceptionInterface
{
    public function __construct(
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message,
            ResultCode::ADMIN_LIMIT_EXCEEDED,
            $previous,
        );
    }

    public function getDiagnostic(): string
    {
        return $this->getMessage();
    }
}
