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

/**
 * Identifies the protocol handler a request routes to.
 *
 * @internal
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum HandlerId: string
{
    case Abandon = 'abandon';
    case Cancel = 'cancel';
    case WhoAmI = 'whoami';
    case PasswordModify = 'password_modify';
    case PasswordPolicyForward = 'password_policy_forward';
    case StartTls = 'start_tls';
    case UnsupportedExtended = 'unsupported_extended';
    case RootDse = 'root_dse';
    case Subschema = 'subschema';
    case Monitor = 'monitor';
    case Paging = 'paging';
    case Sync = 'sync';
    case Search = 'search';
    case Unbind = 'unbind';
    case Compare = 'compare';
    case Dispatch = 'dispatch';
}
