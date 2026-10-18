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

use FreeDSx\Ldap\Operation\ResultCode;

/**
 * Thrown when a received filter nests deeper than the server is willing to decode.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterDepthExceededException extends RuntimeException implements AnswerableExceptionInterface
{
    public function __construct(string $message)
    {
        parent::__construct(
            $message,
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    public function getDiagnostic(): string
    {
        return $this->getMessage();
    }
}
