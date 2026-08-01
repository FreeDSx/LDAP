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
use FreeDSx\Ldap\Schema\Validation\SchemaReferenceValidator;

/**
 * The schema definition files shipped with this package.
 *
 * @internal
 */
enum SchemaResource: string
{
    case Core = 'core.ldif';

    case Nis = 'nis.ldif';

    case PasswordPolicy = 'ppolicy.ldif';

    private const DIRECTORY = 'ldap-schema/';

    /**
     * @throws SchemaParseException
     */
    public function load(): Schema
    {
        $parser = new SubschemaEntryParser(
            references: new SchemaReferenceValidator($this->validationBase()),
        );

        return (new SubschemaLoader(parser: $parser))
            ->fromLdifFile(Resources::path(self::DIRECTORY . $this->value));
    }

    /**
     * The core schema resolves against itself alone; the optional ones build on it.
     */
    private function validationBase(): Schema
    {
        return $this === self::Core
            ? new Schema()
            : self::Core->load();
    }
}
