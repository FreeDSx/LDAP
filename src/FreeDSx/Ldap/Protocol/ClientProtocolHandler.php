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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Socket\Exception\ConnectionException as SocketException;
use FreeDSx\Socket\SocketPool;

/**
 * Handles client specific protocol communication details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    const ROOTDSE_ATTRIBUTES = [
        'supportedSaslMechanisms',
        'supportedControl',
        'supportedLDAPVersion',
    ];

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

    /**
     * @var null|Entry
     */
    protected $rootDse;

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
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * Make a single search request to fetch the RootDSE. Handle the various errors that could occur.
     *
     * @throws ConnectionException
     * @throws OperationException
     * @throws UnsolicitedNotificationException
     */
    public function fetchRootDse(bool $reload = false): Entry
    {
        if ($reload === false && $this->rootDse !== null) {
            return $this->rootDse;
        }
        $message = $this->send(Operations::read('', ...self::ROOTDSE_ATTRIBUTES));
        if ($message === null) {
            throw new OperationException('Expected a search response for the RootDSE. None received.');
        }

        $searchResponse = $message->getResponse();
        if (!$searchResponse instanceof SearchResponse) {
            throw new OperationException('Expected a search response for the RootDSE. None received.');
        }

        $entry = $searchResponse->getEntries()->first();
        if ($entry === null) {
            throw new OperationException('Expected a single entry for the RootDSE. None received.');
        }
        $this->rootDse = $entry;

        return $entry;
    }

    /**
     * @throws ConnectionException
     * @throws OperationException
     * @throws UnsolicitedNotificationException
     */
    public function send(RequestInterface $request, Control ...$controls): ?LdapMessageResponse
    {
        try {
            $context = new ClientProtocolContext(
                $request,
                $controls,
                $this,
                $this->queue(),
                $this->options
            );

            $messageFrom = $this->protocolHandlerFactory->forRequest($request)->handleRequest($context);
            $messageTo = $context->messageToSend();
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
    public function isConnected(): bool
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
