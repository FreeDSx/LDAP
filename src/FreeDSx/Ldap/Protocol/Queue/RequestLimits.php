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
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

use function min;

/**
 * The limits a server applies to each request it reads from a client.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequestLimits
{
    /**
     * @param ServerAuthorization $authorization the session whose bind decides which size limit applies.
     * @param int $maxSize the largest request in bytes, or 0 for no limit.
     * @param int $maxAnonymousSize the largest request in bytes without an authenticated bind, or 0 for no own limit.
     * @param int $maxElements the most ASN.1 elements a request may hold, or 0 for no limit.
     * @param int $readTimeout the seconds a request may take to finish arriving, or 0 for no limit.
     */
    public function __construct(
        private ServerAuthorization $authorization,
        private int $maxSize = 0,
        private int $maxAnonymousSize = 0,
        private int $maxElements = 0,
        private int $readTimeout = 0,
    ) {}

    /**
     * The seconds a request may take to finish arriving, or 0 for no limit.
     */
    public function readTimeout(): int
    {
        return $this->readTimeout;
    }

    /**
     * The largest request in bytes the session may send now, or 0 for no limit.
     */
    public function maxSize(): int
    {
        if ($this->maxAnonymousSize === 0 || $this->hasAuthenticatedBind()) {
            return $this->maxSize;
        }
        if ($this->maxSize === 0) {
            return $this->maxAnonymousSize;
        }

        return min(
            $this->maxSize,
            $this->maxAnonymousSize,
        );
    }

    /**
     * The decoding options that hold a request to the given size and the element limit.
     */
    public function encoderOptions(int $maxSize): EncoderOptions
    {
        return new EncoderOptions(
            maxLength: $maxSize,
            maxElements: $this->maxElements,
        );
    }

    /**
     * The elements a request's nested parts may still hold after its main decode, or null when there is no limit.
     */
    public function elementsLeftAfter(int $elementCount): ?int
    {
        if ($this->maxElements === 0) {
            return null;
        }

        return $this->maxElements - $elementCount;
    }

    private function hasAuthenticatedBind(): bool
    {
        // The token's kind decides, as a session counts as authenticated whenever authentication is not required.
        return $this->authorization->getToken() instanceof AuthenticatedTokenInterface;
    }
}
