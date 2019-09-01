<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Socket\SocketPool;
use FreeDSx\Socket\Exception\ConnectionException as SocketException;

/**
 * Handles client specific protocol communication details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    /**
     * @var SocketPool
     */
    protected $pool;

    /**
     * @var LdapQueue
     */
    protected $queue;

    /**
     * @var array
     */
    protected $options;

    /**
     * @var ControlBag
     */
    protected $controls;

    /**
     * @var ClientProtocolHandlerFactory
     */
    protected $protocolHandlerFactory;

    public function __construct(array $options, LdapQueue $queue = null, SocketPool $pool = null, ClientProtocolHandlerFactory $clientProtocolHandlerFactory = null)
    {
        $this->options = $options;
        $this->pool = $pool ?? new SocketPool($options);
        $this->protocolHandlerFactory = $clientProtocolHandlerFactory ?? new ClientProtocolHandlerFactory();
        $this->controls = new ControlBag();
        $this->queue = $queue;
    }

    /**
     * @return ControlBag
     */
    public function controls() : ControlBag
    {
        return $this->controls;
    }

    /**
     * @param RequestInterface $request
     * @param Control ...$controls
     * @return LdapMessageResponse|null
     */
    public function send(RequestInterface $request, Control ...$controls) : ?LdapMessageResponse
    {
        $messageTo = new LdapMessageRequest(
            $this->queue()->generateId(),
            $request,
            ...\array_merge($this->controls->toArray(), $controls)
        );

        try {
            $messageFrom = $this->protocolHandlerFactory->forRequest($messageTo->getRequest())->handleRequest(
                $messageTo,
                $this->queue(),
                $this->options
            );
        } catch (UnsolicitedNotificationException $exception) {
            if ($exception->getOid() === ExtendedResponse::OID_NOTICE_OF_DISCONNECTION) {
                $this->queue()->close();
                throw new ConnectionException(
                    sprintf('The remote server has disconnected the session. %s', $exception->getMessage()),
                    $exception->getCode()
                );
            }

            throw $exception;
        } catch (SocketException $exception) {
            throw new ConnectionException(
                $exception->getMessage(),
                $exception->getCode(),
                $exception
            );
        }
        if ($messageFrom) {
            $messageFrom = $this->protocolHandlerFactory->forResponse($messageTo->getRequest(), $messageFrom->getResponse())->handleResponse(
                $messageTo,
                $messageFrom,
                $this->queue(),
                $this->options
            );
        }

        return $messageFrom;
    }

    /**
     * @return bool
     */
    public function isConnected() : bool
    {
        return $this->queue && $this->queue->isConnected();
    }

    /**
     * @throws SocketException
     */
    protected function queue() : LdapQueue
    {
        if ($this->queue === null) {
            $this->queue = LdapQueue::usingSocketPool($this->pool, new LdapEncoder());
        }

        return $this->queue;
    }
}
