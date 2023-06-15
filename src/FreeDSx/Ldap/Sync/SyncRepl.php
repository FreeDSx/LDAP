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

namespace FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\Sync\SyncDoneControl;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SyncRequest;
use FreeDSx\Ldap\Operations;

/**
 * A helper class for an LDAP Content Synchronization Operation, described by RFC 4533.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 * @see https://tools.ietf.org/html/rfc4533
 */
final class SyncRepl
{
    private SyncRequest $syncRequest;

    private LdapClient $client;

    private ?string $cookie = null;

    private ControlBag $controls;

    public function __construct(
        LdapClient $client,
        ?SyncRequest $syncRequest = null
    ) {
        $this->client = $client;
        $this->syncRequest = $syncRequest ?? Operations::sync();
        $this->controls = new ControlBag();
    }

    public function usingSyncRequest(SyncRequest $syncRequest): self
    {
        $this->syncRequest = $syncRequest;

        return $this;
    }

    public function controls(): ControlBag
    {
        return $this->controls;
    }

    public function useCookie(?string $cookie): self
    {
        $this->cookie = $cookie;

        return $this;
    }

    public function getCookie(): ?string
    {
        return $this->cookie;
    }

    public function sync(): void
    {
        $this->getResponseAndUpdateCookie();
    }

    private function getResponseAndUpdateCookie(Control ...$controls): void
    {
        $messageResponse = $this->client->sendAndReceive(
            $this->syncRequest,
            ...$controls,
            ...$this->controls->toArray(),
        );

        $searchDone = $messageResponse->controls()
            ->getByClass(SyncDoneControl::class);

        if ($searchDone === null) {
            throw new ProtocolException(sprintf(
                'Expected a "%s" control, but none was received.',
                SyncDoneControl::class,
            ));
        }

        $this->cookie = $searchDone->getCookie();
    }
}
