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

use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Socket\Exception\ReadTimeoutException;

use function microtime;
use function sprintf;

/**
 * The limits a request on one connection must arrive within: its size, its elements and its time.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class RequestArrival
{
    /**
     * The request size the encoder holds, or null until the first decode sets it.
     */
    private ?int $maxSize = null;

    /**
     * When the request partly received must have fully arrived, or null until a wait finds one.
     */
    private ?float $deadline = null;

    public function __construct(private readonly RequestLimits $limits) {}

    /**
     * Holds the encoder to the size the session's bind allows now.
     */
    public function limitDecoding(LdapEncoder $encoder): void
    {
        $maxSize = $this->limits->maxSize();
        if ($maxSize === $this->maxSize) {
            return;
        }
        $this->maxSize = $maxSize;
        $encoder->setOptions($this->limits->encoderOptions($maxSize));
    }

    /**
     * The elements a request's nested parts may still hold, or null when there is no limit.
     */
    public function elementsLeftAfter(int $elementCount): ?int
    {
        return $this->limits->elementsLeftAfter($elementCount);
    }

    /**
     * The seconds the next read may wait on a request that has begun to arrive, or null to leave it to the idle timeout.
     */
    public function readTimeout(bool $isRequestArriving): ?float
    {
        $timeout = $this->limits->readTimeout();
        // Between requests only the idle timeout applies.
        if ($timeout === 0 || !$isRequestArriving) {
            return null;
        }
        $this->deadline ??= microtime(true) + $timeout;

        return $this->deadline - microtime(true);
    }

    /**
     * The read that timed out, reported as the request taking too long to arrive.
     */
    public function timedOut(ReadTimeoutException $timeout): never
    {
        throw new ReadTimeoutException(
            sprintf(
                'The request did not finish arriving within %d seconds.',
                $this->limits->readTimeout(),
            ),
            previous: $timeout,
        );
    }

    /**
     * Starts the time over for the next request.
     */
    public function arrived(): void
    {
        $this->deadline = null;
    }
}
