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

namespace FreeDSx\Ldap\Protocol;

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ClientProtocolContext;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Sasl\Exception\SaslException;
use FreeDSx\Socket\Exception\ConnectionException as SocketException;
use FreeDSx\Socket\SocketPool;

/**
 * Handles client specific protocol communication details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    public const ROOTDSE_ATTRIBUTES = [
        'supportedSaslMechanisms',
        'supportedControl',
        'supportedLDAPVersion',
    ];

    private SocketPool $pool;

    private ?ClientQueue $queue;

    private array $options;

    private ControlBag $controls;

    private ClientProtocolHandlerFactory $protocolHandlerFactory;

    private ?Entry $rootDse = null;

    public function __construct(
        array $options,
        ClientQueue $queue = null,
        SocketPool $pool = null,
        ClientProtocolHandlerFactory $clientProtocolHandlerFactory = null
    ) {
        $this->options = $options;
        $this->pool = $pool ?? new SocketPool($options);
        $this->protocolHandlerFactory = $clientProtocolHandlerFactory ?? new ClientProtocolHandlerFactory();
        $this->controls = new ControlBag();
        $this->queue = $queue;
    }

    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * Make a single search request to fetch the RootDSE. Handle the various errors that could occur.
     *
     * @throws ConnectionException
     * @throws OperationException
     * @throws SocketException
     * @throws UnsolicitedNotificationException
     * @throws EncoderException
     * @throws BindException
     * @throws ProtocolException
     * @throws ReferralException
     * @throws SaslException
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
     * @throws SocketException
     * @throws UnsolicitedNotificationException
     * @throws EncoderException
     * @throws BindException
     * @throws ProtocolException
     * @throws ReferralException
     * @throws SaslException
     */
    public function send(
        RequestInterface $request,
        Control ...$controls
    ): ?LdapMessageResponse {
        try {
            $context = new ClientProtocolContext(
                request: $request,
                controls: $controls,
                protocolHandler: $this,
                queue: $this->queue(),
                options: $this->options,
            );

            $messageFrom = $this->protocolHandlerFactory
                ->forRequest($request)
                ->handleRequest($context);

            $messageTo = $context->messageToSend();
            if ($messageFrom !== null) {
                $messageFrom = $this->protocolHandlerFactory->forResponse(
                    $messageTo->getRequest(),
                    $messageFrom->getResponse()
                )->handleResponse(
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

    public function isConnected(): bool
    {
        return ($this->queue !== null && $this->queue->isConnected());
    }

    /**
     * @throws SocketException
     */
    private function queue(): ClientQueue
    {
        if ($this->queue === null) {
            $this->queue = new ClientQueue($this->pool);
        }

        return $this->queue;
    }
}
