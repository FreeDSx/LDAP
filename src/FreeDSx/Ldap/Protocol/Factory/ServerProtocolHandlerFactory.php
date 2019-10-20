<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerProtocolHandlerInterface;

/**
 * Determines the correct handler for the request.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerProtocolHandlerFactory
{
    public function get(RequestInterface $request): ServerProtocolHandlerInterface
    {
        if ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI) {
            return new ServerProtocolHandler\ServerWhoAmIHandler();
        } elseif ($request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS) {
            return new ServerProtocolHandler\ServerStartTlsHandler();
        } elseif ($this->isRootDseSearch($request)) {
            return new ServerProtocolHandler\ServerRootDseHandler();
        } elseif ($request instanceof SearchRequest) {
            return new ServerProtocolHandler\ServerSearchHandler();
        } elseif ($request instanceof UnbindRequest) {
            return new ServerProtocolHandler\ServerUnbindHandler();
        } else {
            return new ServerProtocolHandler\ServerDispatchHandler();
        }
    }

    /**
     * @param RequestInterface $request
     * @return bool
     */
    protected function isRootDseSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
                && ((string)$request->getBaseDn() === '');
    }
}
