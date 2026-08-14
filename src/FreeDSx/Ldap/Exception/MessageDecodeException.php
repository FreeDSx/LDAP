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
 * A message whose envelope parsed but whose contents did not, so it can still be answered by its ID.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MessageDecodeException extends ProtocolException
{
    public function __construct(
        private readonly int $messageId,
        private readonly int $protocolOpTag,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            $message,
            0,
            $previous,
        );
    }

    public function getMessageId(): int
    {
        return $this->messageId;
    }

    /**
     * The tag of the operation that failed, which fixes the response type owed to the client.
     */
    public function getProtocolOpTag(): int
    {
        return $this->protocolOpTag;
    }
}
