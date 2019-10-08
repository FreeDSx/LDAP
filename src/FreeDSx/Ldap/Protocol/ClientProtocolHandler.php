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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
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
     * @var ClientQueue|null
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

    public function __construct(array $options, ClientQueue $queue = null, SocketPool $pool = null, ClientProtocolHandlerFactory $clientProtocolHandlerFactory = null)
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
     * @throws ConnectionException
     * @throws UnsolicitedNotificationException
     * @throws OperationException
     */
    public function send(RequestInterface $request, Control ...$controls) : ?LdapMessageResponse
    {
        try {
            $messageTo = new LdapMessageRequest(
                $this->queue()->generateId(),
                $request,
                ...\array_merge($this->controls->toArray(), $controls)
            );

            $messageFrom = $this->protocolHandlerFactory->forRequest($messageTo->getRequest())->handleRequest(
                $messageTo,
                $this->queue(),
                $this->options
            );
            if ($messageFrom !== null) {
                $messageFrom = $this->protocolHandlerFactory->forResponse($messageTo->getRequest(), $messageFrom->getResponse())->handleResponse(
                    $messageTo,
                    $messageFrom,
                    $this->queue(),
                    $this->options
                );
            }

            return $messageFrom;
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
    }

    /**
     * @return bool
     */
    public function isConnected() : bool
    {
        return ($this->queue !== null && $this->queue->isConnected());
    }

    /**
     * @throws SocketException
     */
    protected function queue(): ClientQueue
    {
        if ($this->queue === null) {
            $this->queue = new ClientQueue($this->pool);
        }

        return $this->queue;
    }
}
