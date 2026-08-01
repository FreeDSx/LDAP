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

namespace FreeDSx\Ldap\Schema\Parser;

/**
 * How the value following a schema definition keyword is read.
 *
 * @internal
 */
enum KeywordKind
{
    /**
     * The keyword stands alone with no value, such as OBSOLETE.
     */
    case Flag;

    /**
     * A single quoted string, such as DESC.
     */
    case QdString;

    /**
     * One quoted string or a parenthesized list of them, such as NAME.
     */
    case QdStrings;

    /**
     * A single OID, such as EQUALITY.
     */
    case Oid;

    /**
     * One OID or a parenthesized list of them, such as MUST.
     */
    case Oids;
}
