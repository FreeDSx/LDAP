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

namespace FreeDSx\Ldap\Server\Config;

/**
 * How much of a session the server refuses to serve over an unprotected connection.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum ConfidentialityRequirement
{
    /**
     * Anything goes, including a password in the clear.
     */
    case None;

    /**
     * Binds that put a credential on the wire, leaving anonymous reads available in the clear.
     */
    case CredentialBind;

    /**
     * Every request, so nothing about the directory crosses an unprotected connection.
     */
    case AllOperations;
}
