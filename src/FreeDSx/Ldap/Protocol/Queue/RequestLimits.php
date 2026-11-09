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

namespace FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Asn1\Encoder\EncoderOptions;

/**
 * The limits a server applies to each request it reads from a client.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequestLimits
{
    /**
     * @param int $maxSize the largest request in bytes, or 0 for no limit.
     * @param int $maxElements the most ASN.1 elements a request may hold, or 0 for no limit.
     */
    public function __construct(
        private int $maxSize = 0,
        private int $maxElements = 0,
    ) {}

    /**
     * The decoding options that hold a request to these limits.
     */
    public function encoderOptions(): EncoderOptions
    {
        return new EncoderOptions(
            maxLength: $this->maxSize,
            maxElements: $this->maxElements,
        );
    }
}
