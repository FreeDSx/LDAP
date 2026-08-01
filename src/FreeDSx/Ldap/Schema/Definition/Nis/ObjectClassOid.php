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

namespace FreeDSx\Ldap\Schema\Definition\Nis;

/**
 * OIDs, names, and descriptions for the RFC 2307 POSIX account/group/shadow object classes.
 *
 * @api
 */
final class ObjectClassOid
{
    public const OID_POSIX_ACCOUNT = '1.3.6.1.1.1.2.0';

    public const NAME_POSIX_ACCOUNT = 'posixAccount';

    public const DESC_POSIX_ACCOUNT = 'abstraction of an account with POSIX attributes';

    public const OID_SHADOW_ACCOUNT = '1.3.6.1.1.1.2.1';

    public const NAME_SHADOW_ACCOUNT = 'shadowAccount';

    public const DESC_SHADOW_ACCOUNT = 'additional attributes for shadow passwords';

    public const OID_POSIX_GROUP = '1.3.6.1.1.1.2.2';

    public const NAME_POSIX_GROUP = 'posixGroup';

    public const DESC_POSIX_GROUP = 'abstraction of a group of accounts';

    private function __construct() {}
}
