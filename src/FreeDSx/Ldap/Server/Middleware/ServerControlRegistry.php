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
     * Handlers whose requests carry no response, so the critical-control check does not apply.
     */
    private const EXEMPT_HANDLERS = [
        HandlerId::Abandon,
        HandlerId::Unbind,
    ];

    /**
     * A bind is answered in middleware rather than routed to a handler, so it has no HandlerId to look up.
     *
     * Proxied authorization is absent deliberately: RFC 4370 §3 does not list Bind among the operations it may
     * accompany, and its criticality must be TRUE, so it can only ever be refused here.
     *
     * @return list<string>
     */
    public function supportedControlsForBind(): array
    {
        return [
            Control::OID_MANAGE_DSA_IT,
            Control::OID_PWD_POLICY,
        ];
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
    public function supportedControlsFor(HandlerId $id): array
    {
        return [
            ...self::GLOBAL_CONTROLS,
            ...$this->handlerControlsFor($id),
        ];
    }

    /**
     * @return list<string>
     */
    private function handlerControlsFor(HandlerId $id): array
    {
        return match ($id) {
            HandlerId::Search => [
                Control::OID_SORTING,
                Control::OID_ASSERTION,
                Control::OID_SUBENTRIES,
            ],
            HandlerId::Paging => [
                Control::OID_PAGING,
                Control::OID_SORTING,
                Control::OID_ASSERTION,
                Control::OID_SUBENTRIES,
            ],
            HandlerId::Dispatch => [
                Control::OID_RELAX_RULES,
                Control::OID_ASSERTION,
                Control::OID_PRE_READ,
                Control::OID_POST_READ,
                Control::OID_SUBTREE_DELETE,
            ],
            HandlerId::Sync => [
                Control::OID_SYNC_REQUEST,
            ],
            default => [],
        };
    }
}
