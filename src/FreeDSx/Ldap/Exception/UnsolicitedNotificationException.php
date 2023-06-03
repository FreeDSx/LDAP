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

use Throwable;

/**
 * Thrown when an unsolicited notification is received. Holds the error, code, and OID of the notification type.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class UnsolicitedNotificationException extends ProtocolException
{
    private string $oid;

    public function __construct(
        string $message = "",
        int $code = 0,
        Throwable $previous = null,
        string $oid = ""
    ) {
        $this->oid = $oid;
        parent::__construct(
            $message,
            $code,
            $previous
        );
    }

    /**
     * Get the name OID identifying the unsolicited notification.
     */
    public function getOid(): string
    {
        return $this->oid;
    }
}
