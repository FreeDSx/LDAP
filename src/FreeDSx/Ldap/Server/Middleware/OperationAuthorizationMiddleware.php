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

namespace FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;
use FreeDSx\Ldap\Protocol\Factory\HandlerRouteResolverInterface;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\OperationTargetDn;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Authorizes the operation before dispatch and audits denials.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class OperationAuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * @param list<string> $privilegedControls Control OIDs that require an explicit ControlRule grant before use.
     * @param list<string> $privilegedExtendedOps Extended operation OIDs that require an explicit grant before use.
     */
    public function __construct(
        private HandlerRouteResolverInterface $routeResolver,
        private AccessControlInterface $accessControl,
        private Dn $subschemaEntry,
        private array $privilegedControls = [Control::OID_RELAX_RULES],
        private array $privilegedExtendedOps = [],
    ) {}

    /**
     * @throws OperationException
     */
    public function process(
        ServerRequestContext $context,
        MiddlewareHandlerInterface $next,
    ): ResponseStream {
        $this->authorizePrivilegedExtendedOperation($context);

        $routeId = $this->routeResolver->routeIdFor(
            $context->message->getRequest(),
            $context->message->controls(),
        );

        if ($routeId === HandlerId::Search || $routeId === HandlerId::Paging) {
            $this->authorizeSearch(
                $context->message,
                $context->tokenOrFail(),
            );
        } elseif ($routeId === HandlerId::Sync) {
            $this->authorizeSync(
                $context->message,
                $context->tokenOrFail(),
            );
        } elseif ($routeId === HandlerId::Monitor) {
            $this->accessControl->authorizeOperation(
                OperationType::Search,
                $context->tokenOrFail(),
                new Dn(ServerMonitorHandler::DN),
            );
        } elseif ($routeId === HandlerId::Subschema) {
            $this->accessControl->authorizeOperation(
                OperationType::Search,
                $context->tokenOrFail(),
                $this->subschemaEntry,
            );
        } elseif ($routeId === HandlerId::RootDse) {
            // Left ungated on purpose. RFC 4513 section 5.2.1.5 has servers allow all clients, including anonymous
            // ones, to read supportedSASLMechanisms before authenticating, and comparing that list before and after a
            // SASL exchange is how a client detects a downgrade attack. Per-attribute read rules still apply.
        } elseif ($routeId === HandlerId::Dispatch) {
            $this->authorizeDispatch(
                $context->message,
                $context->tokenOrFail(),
            );
        }

        return $next->handle($context);
    }

    /**
     * @throws OperationException
     */
    private function authorizePrivilegedExtendedOperation(ServerRequestContext $context): void
    {
        $request = $context->message->getRequest();

        if (!$request instanceof ExtendedRequest) {
            return;
        }

        if (!in_array($request->getName(), $this->privilegedExtendedOps, true)) {
            return;
        }

        $this->accessControl->authorizeExtendedOperation(
            $context->tokenOrFail(),
            $request->getName(),
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeSearch(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $baseDn = $request->getBaseDn();

        if ($baseDn === null) {
            return;
        }

        $this->accessControl->authorizeOperation(
            OperationType::Search,
            $token,
            $baseDn,
        );
    }

    /**
     * Gates a content-synchronization search on the privileged sync-request control, targeted at its base DN.
     *
     * @throws OperationException
     */
    private function authorizeSync(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            return;
        }

        $this->authorizeControls(
            $request->getBaseDn(),
            $message->controls(),
            $token,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeDispatch(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $request = $message->getRequest();

        $this->authorizeRequest(
            $request,
            $token,
        );
        $this->authorizeWriteAttributes(
            $request,
            $token,
        );

        if ($request instanceof CompareRequest) {
            // Normalize away attribute options so a rule on the base type still applies.
            $this->accessControl->authorizeAttribute(
                $token,
                $request->getDn(),
                $this->attributeFromString($request->getFilter()->getAttribute())->getName(),
                AttributeAccess::Read,
            );

            return;
        }

        $this->authorizeControls(
            OperationTargetDn::of($request),
            $message->controls(),
            $token,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeRequest(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof ModifyDnRequest) {
            $this->authorizeModifyDn(
                $request,
                $token,
            );

            return;
        }

        $operationType = OperationType::fromRequest($request);

        if ($operationType === null || $operationType === OperationType::Search) {
            return;
        }

        $dn = OperationTargetDn::of($request);

        if ($dn === null) {
            return;
        }

        $this->accessControl->authorizeOperation(
            $operationType,
            $token,
            $dn,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeModifyDn(
        ModifyDnRequest $request,
        TokenInterface $token,
    ): void {
        $this->accessControl->authorizeOperation(
            OperationType::ModifyDn,
            $token,
            $request->getDn(),
        );

        $newParentDn = $request->getNewParentDn();

        if ($newParentDn === null) {
            return;
        }

        $this->accessControl->authorizeOperation(
            OperationType::ModifyDn,
            $token,
            $newParentDn,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeWriteAttributes(
        RequestInterface $request,
        TokenInterface $token,
    ): void {
        if ($request instanceof AddRequest) {
            $dn = $request->getEntry()->getDn();
            foreach ($request->getEntry()->getAttributes() as $attribute) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $dn,
                    $attribute->getName(),
                    AttributeAccess::Write,
                );
            }

            return;
        }

        if ($request instanceof ModifyRequest) {
            $dn = $request->getDn();
            foreach ($request->getChanges() as $change) {
                $this->accessControl->authorizeAttribute(
                    $token,
                    $dn,
                    $change->getAttribute()->getName(),
                    AttributeAccess::Write,
                );
            }
        }
    }

    /**
     * Wraps a raw attribute description so getName() can normalize away any attribute options.
     */
    private function attributeFromString(string $attribute): Attribute
    {
        return new Attribute($attribute);
    }

    /**
     * Authorizes any privileged control attached to the request before it is dispatched.
     *
     * @throws OperationException
     */
    private function authorizeControls(
        ?Dn $dn,
        ControlBag $controls,
        TokenInterface $token,
    ): void {
        if ($dn === null) {
            return;
        }

        foreach ($this->privilegedControls as $oid) {
            if (!$controls->has($oid)) {
                continue;
            }

            $this->accessControl->authorizeControl(
                $token,
                $dn,
                $oid,
            );
        }
    }
}
