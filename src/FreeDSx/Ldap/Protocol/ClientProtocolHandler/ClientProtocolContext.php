<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ClientProtocolHandler;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;

/**
 * Contains client protocol specific details that get passed to the request handlers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolContext
{
    /**
     * @var ClientProtocolHandler
     */
    protected $protocolHandler;

    /**
     * @var ClientQueue
     */
    protected $clientQueue;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var RequestInterface
     */
    protected $request;

    /**
     * @var Control[]
     */
    protected $controls;

    /**
     * @var LdapMessageRequest
     */
    protected $sentMessage;

    public function __construct(
        RequestInterface $request,
        array $controls,
        ClientProtocolHandler $protocolHandler,
        ClientQueue $queue,
        array $options
    ) {
        $this->request = $request;
        $this->controls = $controls;
        $this->protocolHandler = $protocolHandler;
        $this->clientQueue = $queue;
        $this->options = $options;
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    public function getControls(): array
    {
        return $this->controls;
    }

    public function getProtocolHandler(): ClientProtocolHandler
    {
        return $this->protocolHandler;
    }

    public function getQueue(): ClientQueue
    {
        return $this->clientQueue;
    }

    public function getOptions(): array
    {
        return $this->options;
    }

    public function messageToSend(): LdapMessageRequest
    {
        if ($this->sentMessage !== null) {
            return $this->sentMessage;
        }
        $this->sentMessage = new LdapMessageRequest(
            $this->clientQueue->generateId(),
            $this->request,
            ...$this->controls
        );

        return $this->sentMessage;
    }

    /**
     * @param bool $reload force reload the RootDSE
     */
    public function getRootDse(bool $reload = false): Entry
    {
        return $this->protocolHandler->fetchRootDse($reload);
    }
}
