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

namespace FreeDSx\Ldap\Schema\Definition;

/**
 * RFC 4512 schema description-string keywords used by definition value objects.
 */
final class DefinitionKeyword
{
    public const NAME = 'NAME';

    public const DESC = 'DESC';

    public const OBSOLETE = 'OBSOLETE';

    public const SYNTAX = 'SYNTAX';

    public const SUP = 'SUP';

    public const EQUALITY = 'EQUALITY';

    public const ORDERING = 'ORDERING';

    public const SUBSTR = 'SUBSTR';

    public const SINGLE_VALUE = 'SINGLE-VALUE';

    public const COLLECTIVE = 'COLLECTIVE';

    public const NO_USER_MODIFICATION = 'NO-USER-MODIFICATION';

    public const USAGE = 'USAGE';

    public const MUST = 'MUST';

    public const MAY = 'MAY';

    private function __construct() {}
}
