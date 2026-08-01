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

namespace FreeDSx\Ldap\Operation;

use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;

enum OperationType: string
{
    case Search = 'search';
    case Add = 'add';
    case Modify = 'modify';
    case Delete = 'delete';
    case ModifyDn = 'modify_dn';
    case Compare = 'compare';
    case PasswordModify = 'password_modify';
    case Bind = 'bind';
    case Unbind = 'unbind';
    case Abandon = 'abandon';
    case Extended = 'extended';

    /**
     * The access-controlled operation a request targets, or null for requests that are not authorized by target DN.
     */
    public static function fromRequest(RequestInterface $request): ?self
    {
        return match (true) {
            $request instanceof AddRequest => self::Add,
            $request instanceof ModifyRequest => self::Modify,
            $request instanceof DeleteRequest => self::Delete,
            $request instanceof ModifyDnRequest => self::ModifyDn,
            $request instanceof CompareRequest => self::Compare,
            $request instanceof SearchRequest => self::Search,
            default => null,
        };
    }

    /**
     * The operation type for any request, including the non-access-controlled ones (bind, unbind, abandon, extended).
     */
    public static function classify(RequestInterface $request): self
    {
        return self::fromRequest($request) ?? match (true) {
            $request instanceof BindRequest => self::Bind,
            $request instanceof UnbindRequest => self::Unbind,
            $request instanceof AbandonRequest => self::Abandon,
            // Decoded from the wire this is a plain extended request, so only the OID identifies it.
            $request instanceof ExtendedRequest
                && $request->getName() === ExtendedRequest::OID_PWD_MODIFY => self::PasswordModify,
            default => self::Extended,
        };
    }
}
