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

use function sprintf;

/**
 * Thrown when the change journal no longer retains every record after the position being read from.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class JournalLapsedException extends RuntimeException implements AnswerableExceptionInterface
{
    private const DIAGNOSTIC = 'The change journal no longer covers this synchronization; a full refresh is required.';

    public function __construct(
        int $afterSeq,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            sprintf(
                'The change journal no longer retains every record after seq %d.',
                $afterSeq,
            ),
            ResultCode::SYNCHRONIZATION_REFRESH_REQUIRED,
            $previous,
        );
    }

    public function getDiagnostic(): string
    {
        return self::DIAGNOSTIC;
    }
}
