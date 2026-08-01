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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\SchemaParseException;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaLoadMode;
use FreeDSx\Ldap\Schema\Validation\SchemaReferenceValidator;

use function array_values;

/**
 * Turns the definitions published on a subschema entry into a schema.
 *
 * A matching rule is only read when a comparator implements it, since a description string names a rule but cannot
 * express how it compares. The matchingRuleUse attribute is derived from attribute types and is not read.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubschemaEntryParser
{
    /**
     * @param ?SchemaReferenceValidator $references omit to leave cross-references to whoever merges the result,
     *                                              which is what a schema that is only part of a whole needs
     */
    public function __construct(
        private SchemaDefinitionParser $definitions = new SchemaDefinitionParser(),
        private ?SchemaReferenceValidator $references = null,
    ) {}

    /**
     * @throws SchemaParseException
     */
    public function parse(
        Entry $entry,
        SchemaLoadMode $mode,
    ): Schema {
        $schema = new Schema();

        $syntaxes = $this->parseAll(
            $entry,
            AttributeTypeOid::NAME_LDAP_SYNTAXES,
            $this->definitions->parseLdapSyntax(...),
            $mode,
        );
        foreach ($syntaxes as $syntax) {
            $schema->addSyntax($syntax);
        }

        $rules = $this->parseAll(
            $entry,
            AttributeTypeOid::NAME_MATCHING_RULES,
            $this->definitions->parseMatchingRule(...),
            $mode,
        );
        foreach ($rules as $rule) {
            if ($rule === null) {
                continue;
            }

            $schema->addMatchingRule($rule);
        }

        $types = $this->parseAll(
            $entry,
            AttributeTypeOid::NAME_ATTRIBUTE_TYPES,
            $this->definitions->parseAttributeType(...),
            $mode,
        );
        foreach ($types as $type) {
            $schema->addAttributeType($type);
        }

        $classes = $this->parseAll(
            $entry,
            AttributeTypeOid::NAME_OBJECT_CLASSES,
            $this->definitions->parseObjectClass(...),
            $mode,
        );
        foreach ($classes as $class) {
            $schema->addObjectClass($class);
        }

        $this->references?->validate(
            $schema,
            $mode,
        );

        return $schema;
    }

    /**
     * Parses every value of an attribute, dropping the ones that fail when the mode allows it.
     *
     * @template T
     * @param callable(string): T $parse
     * @return list<T>
     * @throws SchemaParseException
     */
    private function parseAll(
        Entry $entry,
        string $attribute,
        callable $parse,
        SchemaLoadMode $mode,
    ): array {
        $parsed = [];

        foreach ($this->valuesOf($entry, $attribute) as $definition) {
            try {
                $parsed[] = $parse($definition);
            } catch (SchemaParseException $e) {
                if ($mode === SchemaLoadMode::Strict) {
                    throw $e;
                }
            }
        }

        return $parsed;
    }

    /**
     * @return list<string>
     */
    private function valuesOf(
        Entry $entry,
        string $attribute,
    ): array {
        return array_values(
            $entry->get($attribute)?->getValues() ?? [],
        );
    }
}
