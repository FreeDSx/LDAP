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

namespace FreeDSx\Ldap\Protocol\Decoder\Filter;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Exception\AdminLimitExceededException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Decodes one kind of filter from the CHOICE a received filter holds (RFC 4511 4.5.1.7).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterShapeDecoderInterface
{
    /**
     * @param AbstractType<mixed> $type
     * @throws AdminLimitExceededException
     * @throws ProtocolException
     * @throws EncoderException
     */
    public function decode(
        AbstractType $type,
        FilterDecodeRun $run,
    ): FilterInterface;
}
