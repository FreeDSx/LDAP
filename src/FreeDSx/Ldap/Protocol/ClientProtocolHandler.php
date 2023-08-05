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

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ReferralException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\Factory\ClientProtocolHandlerFactory;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Socket\Exception\ConnectionException as SocketException;

/**
 * Handles client specific protocol communication details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    private ?ClientQueue $queue = null;

    public function __construct(
        private readonly ClientOptions $options,
        private readonly ClientQueueInstantiator $clientQueueInstantiator,
        private readonly ClientProtocolHandlerFactory $protocolHandlerFactory,
    ) {
    }

    /**
     * @throws ConnectionException
     * @throws OperationException
     * @throws UnsolicitedNotificationException
     * @throws BindException
     * @throws ReferralException
     */
    public function send(
        RequestInterface $request,
        Control ...$controls
    ): ?LdapMessageResponse {
        try {
            $messageTo = new LdapMessageRequest(
                $this->queue()->generateId(),
                $request,
                ...$this->options->getControls()->toArray(),
                ...$controls,
            );
            $messageFrom = $this->protocolHandlerFactory
                ->forRequest($request)
                ->handleRequest($messageTo);

            if ($messageFrom !== null) {
                $messageFrom = $this->protocolHandlerFactory->forResponse(
                    $messageTo->getRequest(),
                    $messageFrom->getResponse()
                )->handleResponse(
                    $messageTo,
                    $messageFrom,
                );
            }

            return $messageFrom;
        } catch (UnsolicitedNotificationException $exception) {
            if ($exception->isNoticeOfDisconnection()) {
                $this->queue()->close();

                throw new ConnectionException(
                    sprintf(
                        'The remote server has disconnected the session. %s',
                        $exception->getMessage(),
                    ),
                    $exception->getCode(),
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
     * @throws SocketException
     */
    private function queue(): ClientQueue
    {
        if ($this->queue === null) {
            $this->queue = $this->clientQueueInstantiator->make();
        }

        return $this->queue;
    }
}
