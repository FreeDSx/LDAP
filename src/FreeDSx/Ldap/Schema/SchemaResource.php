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

namespace FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Resources;
use FreeDSx\Ldap\Schema\Parser\SubschemaEntryParser;

/**
 * The schema definition files shipped with this package.
 *
 * @api
 */
enum SchemaResource: string implements SchemaSourceInterface
{
    case Core = 'core.ldif';

    case Nis = 'nis.ldif';

    case PasswordPolicy = 'ppolicy.ldif';

    private const DIRECTORY = 'ldap-schema/';

    /**
     * Definitions are parsed strictly, but references are left for whoever merges the sources; the optional
     * schemas build on the core one, so neither resolves on its own.
     *
     * @throws SchemaParseException
     */
    public function load(): Schema
    {
        $loader = new SubschemaLoader(parser: new SubschemaEntryParser());

        return $loader->fromLdifFile(Resources::path(self::DIRECTORY . $this->value));
    }
}
