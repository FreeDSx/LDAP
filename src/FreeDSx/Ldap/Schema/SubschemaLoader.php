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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\LdifParseException;
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Ldif\LdifParser;
use FreeDSx\Ldap\Ldif\Loader\FileLdifLoader;
use FreeDSx\Ldap\Ldif\Loader\LdifLoaderInterface;
use FreeDSx\Ldap\Ldif\Loader\StringLdifLoader;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Schema\Parser\SubschemaEntryParser;

/**
 * Builds a schema from the subschema entry a directory publishes, given a source to read that entry from.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubschemaLoader
{
    public function __construct(
        private SchemaLoadMode $mode = SchemaLoadMode::Strict,
        private SubschemaEntryParser $parser = new SubschemaEntryParser(),
    ) {}

    /**
     * Reads an LDIF file, such as the output of a base search for "+" on cn=subschema.
     *
     * @throws SchemaParseException
     * @throws LdifParseException
     */
    public function fromLdifFile(string $file): Schema
    {
        return $this->fromLdif(new FileLdifLoader($file));
    }

    /**
     * @throws SchemaParseException
     * @throws LdifParseException
     */
    public function fromLdifString(string $ldif): Schema
    {
        return $this->fromLdif(new StringLdifLoader($ldif));
    }

    /**
     * Reads the first entry the LDIF source yields. A subschema is published as a single entry.
     *
     * @throws SchemaParseException
     * @throws LdifParseException
     */
    public function fromLdif(LdifLoaderInterface $ldif): Schema
    {
        foreach ((new LdifParser())->parse($ldif) as $request) {
            if ($request instanceof AddRequest) {
                return $this->fromEntry($request->getEntry());
            }
        }

        throw new SchemaParseException('The LDIF source contains no entry to read schema from.');
    }

    /**
     * Reads a subschema entry already in hand, such as one returned by a live search.
     *
     * @throws SchemaParseException
     */
    public function fromEntry(Entry $entry): Schema
    {
        return $this->parser->parse(
            $entry,
            $this->mode,
        );
    }
}
