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

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\ClientOptions;
use FreeDSx\Ldap\Operation;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Protocol\Queue\ClientQueueInstantiator;
use FreeDSx\Ldap\Protocol\RootDseLoader;

/**
 * Retrieves the correct handler for a specific client protocol request / response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandlerFactory
{
    public function __construct(
        private readonly ClientOptions $clientOptions,
        private readonly ClientQueueInstantiator $queueInstantiator,
        private readonly RootDseLoader $rootDseLoader,
    ) {
    }

    public function forRequest(Request\RequestInterface $request): RequestHandlerInterface
    {
        if ($request instanceof Request\SyncRequest) {
            return new ClientProtocolHandler\ClientSyncHandler(
                queue: $this->queue(),
                options: $this->clientOptions,
            );
        } elseif ($request instanceof Request\SearchRequest) {
            return new ClientProtocolHandler\ClientSearchHandler(
                queue: $this->queue(),
                options: $this->clientOptions,
            );
        } elseif ($request instanceof Request\UnbindRequest) {
            return new ClientProtocolHandler\ClientUnbindHandler($this->queue());
        } elseif ($request instanceof Request\SaslBindRequest) {
            return new ClientProtocolHandler\ClientSaslBindHandler(
                $this->queue(),
                $this->rootDseLoader,
            );
        } else {
            return new ClientProtocolHandler\ClientBasicHandler($this->queue());
        }
    }

    public function forResponse(
        Request\RequestInterface $request,
        Response\ResponseInterface $response
    ): ResponseHandlerInterface {
        if ($response instanceof Response\SearchResultDone || $response instanceof Response\SearchResultEntry || $response instanceof Response\SearchResultReference) {
            return $request instanceof Request\SyncRequest
                ? new ClientProtocolHandler\ClientSyncHandler(
                    queue: $this->queue(),
                    options: $this->clientOptions,
                )
                : new ClientProtocolHandler\ClientSearchHandler(
                    queue: $this->queue(),
                    options: $this->clientOptions,
                );
        } elseif ($response instanceof  Response\SyncInfoMessage) {
            return new ClientProtocolHandler\ClientSyncHandler(
                queue: $this->queue(),
                options: $this->clientOptions,
            );
        } elseif ($response instanceof Operation\LdapResult && $response->getResultCode() === ResultCode::REFERRAL) {
            return new ClientProtocolHandler\ClientReferralHandler($this->clientOptions);
        } elseif ($request instanceof Request\ExtendedRequest && $request->getName() === Request\ExtendedRequest::OID_START_TLS) {
            return new ClientProtocolHandler\ClientStartTlsHandler($this->queue());
        } elseif ($response instanceof Response\ExtendedResponse) {
            return new ClientProtocolHandler\ClientExtendedOperationHandler($this->queue());
        } else {
            return new ClientProtocolHandler\ClientBasicHandler($this->queue());
        }
    }
    
    private function queue(): ClientQueue
    {
        return $this->queueInstantiator->make();
    }
}
