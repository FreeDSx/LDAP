<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Exception;

use Exception;
use FreeDSx\Ldap\Operation\ResultCode;
use Throwable;

/**
 * Used in client-side requests to indicate generic issues with non-success request responses for operations. Used to
 * indicate an error during server-side operation processing. The resulting message and code is used in the
 * LDAP result sent back to the client (when thrown from the request handler).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class OperationException extends Exception
{
    public function __construct(
        string $message = '',
        int $code = ResultCode::OPERATIONS_ERROR,
        Throwable $previous = null
    ) {
        $message = empty($message)
            ? $this->generateMessage($code)
            : $message;

        parent::__construct(
            $message,
            $code,
            $previous
        );
    }

    /**
     * Get the LDAP result code as a short string (as defined in the LDAP RFC).
     *
     * @return string|null
     */
    public function getCodeShort(): ?string
    {
        return ResultCode::MEANING_SHORT[$this->getCode()] ?? null;
    }

    /**
     * Get the LDAP result code meaning description (as defined in the LDAP RFC).
     *
     * @return string|null
     */
    public function getCodeDescription(): ?string
    {
        return ResultCode::MEANING_DESCRIPTION[$this->getCode()] ?? null;
    }

    private function generateMessage(int $resultCode): string
    {
        $message = sprintf('The result code %d was thrown', $resultCode);

        if (isset(ResultCode::MEANING_SHORT[$resultCode])) {
            $message .= sprintf(' (%s)', ResultCode::MEANING_SHORT[$resultCode]);
        }
        if (isset(ResultCode::MEANING_DESCRIPTION[$resultCode])) {
            $message .= '. ' . ResultCode::MEANING_DESCRIPTION[$resultCode];
        }

        return $message;
    }
}
