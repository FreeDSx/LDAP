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

namespace FreeDSx\Ldap\Protocol\Decoder;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Asn1\Type\SequenceType;

/**
 * The parts of a received message read before its operation is decoded.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MessageEnvelope
{
    /**
     * @param AbstractType<mixed> $operation
     */
    public function __construct(
        public SequenceType $pdu,
        public int $messageId,
        public int $operationTag,
        public AbstractType $operation,
    ) {}
}
