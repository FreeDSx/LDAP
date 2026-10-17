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

namespace FreeDSx\Ldap\Server\Operation;

use FreeDSx\Ldap\Exception\AnswerableExceptionInterface;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnrecoverableExceptionInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use Throwable;

/**
 * The result a client is answered with when an operation throws.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait FailureAnswerTrait
{
    /**
     * The result to answer a thrown failure with, or null when it has to end the session instead.
     */
    private function answerFor(Throwable $failure): ?OperationException
    {
        // Returned as-is rather than rebuilt, which is the only way its matched DN survives.
        if ($failure instanceof OperationException) {
            return $failure;
        }
        if ($failure instanceof UnrecoverableExceptionInterface) {
            return null;
        }
        if ($failure instanceof AnswerableExceptionInterface) {
            return new OperationException(
                $failure->getDiagnostic(),
                $failure->getCode(),
                $failure,
            );
        }

        return new OperationException(
            'The result could not be completed.',
            ResultCode::OTHER,
            $failure,
        );
    }
}
