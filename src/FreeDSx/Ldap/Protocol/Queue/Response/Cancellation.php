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

namespace FreeDSx\Ldap\Protocol\Queue\Response;

use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * The control channel between the response writer (which polls the queue) and a streaming producer
 * (which reads the offered abandon/cancel signal after each yield).
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Cancellation
{
    private ?LdapMessageRequest $signal = null;

    /**
     * The writer offers each poll result; nulls are ignored so a real signal is never overwritten.
     */
    public function offer(?LdapMessageRequest $signal): void
    {
        if ($signal !== null) {
            $this->signal = $signal;
        }
    }

    public function isSignalled(): bool
    {
        return $this->signal !== null;
    }

    public function isAbandoned(): bool
    {
        return $this->signal?->getRequest() instanceof AbandonRequest;
    }

    public function isCanceled(): bool
    {
        return $this->signal?->getRequest() instanceof CancelRequest;
    }

    /**
     * RFC 4511 3.1 leaves an operation in flight when the client unbinds with nobody to answer.
     */
    public function isUnbound(): bool
    {
        return $this->signal?->getRequest() instanceof UnbindRequest;
    }

    public function signal(): ?LdapMessageRequest
    {
        return $this->signal;
    }
}
