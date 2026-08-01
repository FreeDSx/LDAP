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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\SchemaSourceInterface;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaReferenceValidator;

/**
 * The schema the server enforces and publishes, and where it is published.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SchemaConfig
{
    private const DEFAULT_SUBSCHEMA_DN = 'cn=Subschema';

    /**
     * Sources merge in order, so a later one overrides an earlier one on OID or name collision. Vendor extensions
     * an overriding definition omits are carried forward, so protections such as X-CONFIDENTIAL survive.
     *
     * @var list<SchemaSourceInterface>
     */
    private array $sources = [
        SchemaResource::Core,
        SchemaResource::Nis,
        SchemaResource::PasswordPolicy,
    ];

    private SchemaValidationMode $validationMode = SchemaValidationMode::Strict;

    private SchemaLoadMode $loadMode = SchemaLoadMode::Strict;

    private Dn $subschemaEntry;

    private ?Schema $resolved = null;

    public function __construct()
    {
        $this->subschemaEntry = new Dn(self::DEFAULT_SUBSCHEMA_DN);
    }

    /**
     * @return list<SchemaSourceInterface>
     */
    public function getSources(): array
    {
        return $this->sources;
    }

    /**
     * Replaces every source, including the ones shipped by default.
     */
    public function setSources(SchemaSourceInterface ...$sources): self
    {
        $this->sources = array_values($sources);
        $this->resolved = null;

        return $this;
    }

    /**
     * Appends to the current sources, so the shipped ones do not have to be restated.
     */
    public function addSource(SchemaSourceInterface ...$sources): self
    {
        foreach ($sources as $source) {
            $this->sources[] = $source;
        }
        $this->resolved = null;

        return $this;
    }

    /**
     * How strictly entries are validated against the schema on add and modify.
     */
    public function getValidationMode(): SchemaValidationMode
    {
        return $this->validationMode;
    }

    public function setValidationMode(SchemaValidationMode $mode): self
    {
        $this->validationMode = $mode;

        return $this;
    }

    /**
     * Whether a definition referencing something no source provides fails the load.
     */
    public function getLoadMode(): SchemaLoadMode
    {
        return $this->loadMode;
    }

    public function setLoadMode(SchemaLoadMode $mode): self
    {
        $this->loadMode = $mode;
        $this->resolved = null;

        return $this;
    }

    /**
     * The entry the schema is published on.
     */
    public function getSubschemaEntry(): Dn
    {
        return $this->subschemaEntry;
    }

    public function setSubschemaEntry(Dn $subschemaEntry): self
    {
        $this->subschemaEntry = $subschemaEntry;

        return $this;
    }

    /**
     * Merges every source into the schema the server runs on, reading each source once.
     *
     * @throws SchemaParseException
     */
    public function resolve(): Schema
    {
        return $this->resolved ??= $this->mergeSources();
    }

    /**
     * @throws SchemaParseException
     */
    private function mergeSources(): Schema
    {
        $schema = new Schema();

        foreach ($this->sources as $source) {
            $schema = $schema->merge($source->load());
        }

        // References are checked here rather than per source, since a source may reference another source. The
        // merged schema stands alone, so there is nothing further to resolve against.
        (new SchemaReferenceValidator(new Schema()))->validate(
            $schema,
            $this->loadMode,
        );

        return $schema;
    }
}
