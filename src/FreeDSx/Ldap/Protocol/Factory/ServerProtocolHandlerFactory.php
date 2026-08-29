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
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Server\GeneratedEntry;
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
        $generated = $this->generatedRouteIdFor($request);
        if ($generated !== null) {
            return $generated;
        }

        return match (true) {
            $request instanceof AbandonRequest => HandlerId::Abandon,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_CANCEL => HandlerId::Cancel,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_WHOAMI => HandlerId::WhoAmI,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PWD_MODIFY => HandlerId::PasswordModify,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_PPOLICY_STATE_FORWARD => HandlerId::PasswordPolicyForward,
            $request instanceof ExtendedRequest && $request->getName() === ExtendedRequest::OID_START_TLS => HandlerId::StartTls,
            $request instanceof ExtendedRequest => HandlerId::UnsupportedExtended,
            $this->isSyncSearch($request, $controls) => HandlerId::Sync,
            $this->isPagingSearch($request, $controls) => HandlerId::Paging,
            $request instanceof SearchRequest => HandlerId::Search,
            $request instanceof UnbindRequest => HandlerId::Unbind,
            default => HandlerId::Dispatch,
        };
    }

    /**
     * The names are reserved unconditionally, but a disabled monitor generates nothing to route to.
     */
    private function generatedRouteIdFor(RequestInterface $request): ?HandlerId
    {
        if (!$request instanceof SearchRequest || $request->getScope() !== SearchRequest::SCOPE_BASE_OBJECT) {
            return null;
        }

        return match (GeneratedEntry::at($request->getBaseDn())) {
            GeneratedEntry::RootDse => HandlerId::RootDse,
            GeneratedEntry::Subschema => HandlerId::Subschema,
            GeneratedEntry::Monitor => $this->options->isMonitorEnabled()
                ? HandlerId::Monitor
                : null,
            null => null,
        };
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
