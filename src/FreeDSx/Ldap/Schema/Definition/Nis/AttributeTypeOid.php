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
 * OIDs, names, and descriptions for the RFC 2307 POSIX account/group/shadow attribute types.
 *
 * @api
 */
final class AttributeTypeOid
{
    public const OID_UID_NUMBER = '1.3.6.1.1.1.1.0';

    public const NAME_UID_NUMBER = 'uidNumber';

    public const DESC_UID_NUMBER = 'an integer uniquely identifying a user in an administrative domain';

    public const OID_GID_NUMBER = '1.3.6.1.1.1.1.1';

    public const NAME_GID_NUMBER = 'gidNumber';

    public const DESC_GID_NUMBER = 'an integer uniquely identifying a group in an administrative domain';

    public const OID_GECOS = '1.3.6.1.1.1.1.2';

    public const NAME_GECOS = 'gecos';

    public const DESC_GECOS = 'the GECOS field; the common name';

    public const OID_HOME_DIRECTORY = '1.3.6.1.1.1.1.3';

    public const NAME_HOME_DIRECTORY = 'homeDirectory';

    public const DESC_HOME_DIRECTORY = 'the absolute path to the home directory';

    public const OID_LOGIN_SHELL = '1.3.6.1.1.1.1.4';

    public const NAME_LOGIN_SHELL = 'loginShell';

    public const DESC_LOGIN_SHELL = 'the path to the login shell';

    public const OID_SHADOW_LAST_CHANGE = '1.3.6.1.1.1.1.5';

    public const NAME_SHADOW_LAST_CHANGE = 'shadowLastChange';

    public const DESC_SHADOW_LAST_CHANGE = 'days since the epoch that the password was last changed';

    public const OID_SHADOW_MIN = '1.3.6.1.1.1.1.6';

    public const NAME_SHADOW_MIN = 'shadowMin';

    public const DESC_SHADOW_MIN = 'minimum days between password changes';

    public const OID_SHADOW_MAX = '1.3.6.1.1.1.1.7';

    public const NAME_SHADOW_MAX = 'shadowMax';

    public const DESC_SHADOW_MAX = 'maximum days a password remains valid';

    public const OID_SHADOW_WARNING = '1.3.6.1.1.1.1.8';

    public const NAME_SHADOW_WARNING = 'shadowWarning';

    public const DESC_SHADOW_WARNING = 'days before expiry that the user is warned';

    public const OID_SHADOW_INACTIVE = '1.3.6.1.1.1.1.9';

    public const NAME_SHADOW_INACTIVE = 'shadowInactive';

    public const DESC_SHADOW_INACTIVE = 'days after expiry that the account is disabled';

    public const OID_SHADOW_EXPIRE = '1.3.6.1.1.1.1.10';

    public const NAME_SHADOW_EXPIRE = 'shadowExpire';

    public const DESC_SHADOW_EXPIRE = 'days since the epoch that the account expires';

    public const OID_SHADOW_FLAG = '1.3.6.1.1.1.1.11';

    public const NAME_SHADOW_FLAG = 'shadowFlag';

    public const DESC_SHADOW_FLAG = 'reserved shadow map flag';

    public const OID_MEMBER_UID = '1.3.6.1.1.1.1.12';

    public const NAME_MEMBER_UID = 'memberUid';

    public const DESC_MEMBER_UID = 'the login name of a group member';

    private function __construct() {}
}
