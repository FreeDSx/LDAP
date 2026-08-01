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
use FreeDSx\Ldap\Schema\Parser\SubschemaEntryParser;

/**
 * Reads schema definitions from a subschema entry in an LDIF file.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LdifSchemaSource implements SchemaSourceInterface
{
    /**
     * @param string $file path to an LDIF file holding a subschema entry
     * @param SchemaLoadMode $mode whether a definition that cannot be parsed fails the load or is skipped
     */
    public function __construct(
        private string $file,
        private SchemaLoadMode $mode = SchemaLoadMode::Strict,
    ) {}

    /**
     * @throws SchemaParseException
     */
    public function load(): Schema
    {
        $loader = new SubschemaLoader(
            $this->mode,
            new SubschemaEntryParser(),
        );

        return $loader->fromLdifFile($this->file);
    }
}
