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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\ServerOptions;

/**
 * Classifies a request to the handler route that will process it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ServerProtocolHandlerFactory implements HandlerRouteResolverInterface
{
    public function __construct(private ServerOptions $options) {}

    public function routeIdFor(
        RequestInterface $request,
        ControlBag $controls,
    ): HandlerId {
        return match (true) {
            $request instanceof AbandonRequest => HandlerId::Abandon,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_CANCEL => HandlerId::Cancel,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI => HandlerId::WhoAmI,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PWD_MODIFY => HandlerId::PasswordModify,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PPOLICY_STATE_FORWARD => HandlerId::PasswordPolicyForward,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS => HandlerId::StartTls,
            $request instanceof ExtendedRequest => HandlerId::UnsupportedExtended,
            $this->isRootDseSearch($request) => HandlerId::RootDse,
            $this->isSubschemaSearch($request) => HandlerId::Subschema,
            $this->isMonitorSearch($request) => HandlerId::Monitor,
            $this->isSyncSearch($request, $controls) => HandlerId::Sync,
            $this->isPagingSearch($request, $controls) => HandlerId::Paging,
            $request instanceof SearchRequest => HandlerId::Search,
            $request instanceof UnbindRequest => HandlerId::Unbind,
            default => HandlerId::Dispatch,
        };
    }

    private function isSubschemaSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $this->isBaseSearchFor(
            $request,
            $this->options->getSubschemaEntry(),
        );
    }

    private function isMonitorSearch(RequestInterface $request): bool
    {
        if (!$this->options->isMonitorEnabled() || !$request instanceof SearchRequest) {
            return false;
        }

        return $this->isBaseSearchFor(
            $request,
            new Dn(ServerMonitorHandler::DN),
        );
    }

    /**
     * Compared as names rather than as text, so a client spelling the DN differently still reaches the handler.
     */
    private function isBaseSearchFor(
        SearchRequest $request,
        Dn $dn,
    ): bool {
        $baseDn = $request->getBaseDn();

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
            && $baseDn !== null
            && $baseDn->equals($dn);
    }

    private function isRootDseSearch(RequestInterface $request): bool
    {
        if (!$request instanceof SearchRequest) {
            return false;
        }

        return $request->getScope() === SearchRequest::SCOPE_BASE_OBJECT
            && $request->getBaseDn()?->isRootDse();
    }

    private function isPagingSearch(
        RequestInterface $request,
        ControlBag $controls,
    ): bool {
        return $request instanceof SearchRequest
            && $controls->has(Control::OID_PAGING);
    }

    private function isSyncSearch(
        RequestInterface $request,
        ControlBag $controls,
    ): bool {
        return $request instanceof SearchRequest
            && $controls->has(Control::OID_SYNC_REQUEST);
    }
}
