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

use FreeDSx\Ldap\Operation;
use FreeDSx\Ldap\Operation\Request;
use FreeDSx\Ldap\Operation\Response;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Protocol\ClientProtocolHandler\ResponseHandlerInterface;

/**
 * Retrieves the correct handler for a specific client protocol request / response.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandlerFactory
{
    public function forRequest(Request\RequestInterface $request): RequestHandlerInterface
    {
        if ($request instanceof Request\SyncRequest) {
            return new ClientProtocolHandler\ClientSyncHandler();
        } elseif ($request instanceof Request\SearchRequest) {
            return new ClientProtocolHandler\ClientSearchHandler();
        } elseif ($request instanceof Request\UnbindRequest) {
            return new ClientProtocolHandler\ClientUnbindHandler();
        } elseif ($request instanceof Request\SaslBindRequest) {
            return new ClientProtocolHandler\ClientSaslBindHandler();
        } else {
            return new ClientProtocolHandler\ClientBasicHandler();
        }
    }

    public function forResponse(
        Request\RequestInterface $request,
        Response\ResponseInterface $response
    ): ResponseHandlerInterface {
        if ($response instanceof Response\SearchResultDone || $response instanceof Response\SearchResultEntry || $response instanceof Response\SearchResultReference) {
            return $request instanceof Request\SyncRequest
                ? new ClientProtocolHandler\ClientSyncHandler()
                : new ClientProtocolHandler\ClientSearchHandler();
        } elseif ($response instanceof  Response\SyncInfoMessage) {
            return new ClientProtocolHandler\ClientSyncHandler();
        } elseif ($response instanceof Operation\LdapResult && $response->getResultCode() === ResultCode::REFERRAL) {
            return new ClientProtocolHandler\ClientReferralHandler();
        } elseif ($request instanceof Request\ExtendedRequest && $request->getName() === Request\ExtendedRequest::OID_START_TLS) {
            return new ClientProtocolHandler\ClientStartTlsHandler();
        } elseif ($response instanceof Response\ExtendedResponse) {
            return new ClientProtocolHandler\ClientExtendedOperationHandler();
        } else {
            return new ClientProtocolHandler\ClientBasicHandler();
        }
    }
}
