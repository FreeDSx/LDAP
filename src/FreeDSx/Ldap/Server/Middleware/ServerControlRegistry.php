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
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Protocol\Factory\HandlerId;

use function in_array;

/**
 * Declares which controls each handler accepts for the critical-control check.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ServerControlRegistry
{
    /**
     * Controls accepted on every handler that runs the check. Proxied authorization is global because the
     * RFC 4370 eligibility gate runs upstream in ProxiedAuthorizationResolver, not here. ManageDsaIT is global
     * because it is recognized server-wide and treated as inert (no referral entries to reinterpret). The password
     * policy request control is global because it may accompany any request, and its criticality may be TRUE.
     *
     * A content sync carries ManageDsaIT critically, so dropping it here would refuse every replication request.
     */
    private const GLOBAL_CONTROLS = [
        Control::OID_PROXY_AUTHORIZATION,
        Control::OID_MANAGE_DSA_IT,
        Control::OID_PWD_POLICY,
    ];

    /**
     * A bind is answered in middleware rather than routed to a handler, so it has no HandlerId to look up.
     *
     * Proxied authorization is absent deliberately: RFC 4370 §3 does not list Bind among the operations it may
     * accompany, and its criticality must be TRUE, so it can only ever be refused here.
     */
    private const BIND_CONTROLS = [
        Control::OID_MANAGE_DSA_IT,
        Control::OID_PWD_POLICY,
    ];

    private const SEARCH_CONTROLS = [
        Control::OID_SORTING,
        Control::OID_ASSERTION,
        Control::OID_SUBENTRIES,
    ];

    private const PAGING_CONTROLS = [
        Control::OID_PAGING,
        Control::OID_SORTING,
        Control::OID_ASSERTION,
        Control::OID_SUBENTRIES,
    ];

    private const SYNC_CONTROLS = [
        Control::OID_SYNC_REQUEST,
    ];

    /**
     * RFC 4527 §3.2 makes post-read appropriate for an add, and §3.1 leaves pre-read to the operations with a
     * before image.
     */
    private const ADD_CONTROLS = [
        Control::OID_RELAX_RULES,
        Control::OID_ASSERTION,
        Control::OID_POST_READ,
    ];

    private const MODIFY_CONTROLS = [
        Control::OID_RELAX_RULES,
        Control::OID_ASSERTION,
        Control::OID_PRE_READ,
        Control::OID_POST_READ,
    ];

    private const MODIFY_DN_CONTROLS = [
        Control::OID_RELAX_RULES,
        Control::OID_ASSERTION,
        Control::OID_PRE_READ,
        Control::OID_POST_READ,
    ];

    /**
     * Post-read is absent because a deleted entry has no after image, and subtree delete applies here alone.
     */
    private const DELETE_CONTROLS = [
        Control::OID_RELAX_RULES,
        Control::OID_ASSERTION,
        Control::OID_PRE_READ,
        Control::OID_SUBTREE_DELETE,
    ];

    /**
     * A compare reads rather than updates, so it takes neither the read-entry pair nor relax.
     */
    private const COMPARE_CONTROLS = [
        Control::OID_ASSERTION,
    ];

    /**
     * Handlers whose requests carry no response, so the critical-control check does not apply.
     */
    private const EXEMPT_HANDLERS = [
        HandlerId::Abandon,
        HandlerId::Unbind,
    ];

    /**
     * @return list<string>
     */
    public function supportedControlsForBind(): array
    {
        return self::BIND_CONTROLS;
    }

    public function appliesTo(HandlerId $id): bool
    {
        return !in_array(
            $id,
            self::EXEMPT_HANDLERS,
            true,
        );
    }

    /**
     * @return list<string>
     */
    public function supportedControlsFor(
        HandlerId $id,
        RequestInterface $request,
    ): array {
        return [
            ...self::GLOBAL_CONTROLS,
            ...$this->handlerControlsFor($id, $request),
        ];
    }

    /**
     * @return list<string>
     */
    private function handlerControlsFor(
        HandlerId $id,
        RequestInterface $request,
    ): array {
        return match ($id) {
            HandlerId::Search => self::SEARCH_CONTROLS,
            HandlerId::Paging => self::PAGING_CONTROLS,
            HandlerId::Dispatch => $this->dispatchControlsFor($request),
            HandlerId::Sync => self::SYNC_CONTROLS,
            default => [],
        };
    }

    /**
     * One handler serves five operations whose control vocabularies differ, so the request decides rather than
     * the route it took (RFC 4511 §4.1.11, RFC 4527 §3.1 and §3.2).
     *
     * @return list<string>
     */
    private function dispatchControlsFor(RequestInterface $request): array
    {
        return match (true) {
            $request instanceof AddRequest => self::ADD_CONTROLS,
            $request instanceof ModifyRequest => self::MODIFY_CONTROLS,
            $request instanceof ModifyDnRequest => self::MODIFY_DN_CONTROLS,
            $request instanceof DeleteRequest => self::DELETE_CONTROLS,
            $request instanceof CompareRequest => self::COMPARE_CONTROLS,
            default => [],
        };
    }
}
