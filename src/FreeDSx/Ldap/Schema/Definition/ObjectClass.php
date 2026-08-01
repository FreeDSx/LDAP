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
 * An object class definition per RFC 4512 §4.1.1.
 */
final readonly class ObjectClass
{
    use DefinitionStringTrait;

    /**
     * @param list<string> $names
     * @param list<string> $superClassOids
     * @param list<string> $must attribute type OIDs or names required by this class
     * @param list<string> $may attribute type OIDs or names permitted by this class
     * @param array<string, list<string>> $extensions
     */
    public function __construct(
        public string $oid,
        public array $names,
        public ObjectClassType $type = ObjectClassType::StructuralClass,
        public array $superClassOids = [],
        public array $must = [],
        public array $may = [],
        public ?string $desc = null,
        public bool $obsolete = false,
        public array $extensions = [],
    ) {}

    /**
     * Returns a copy carrying the given extensions in place of the current ones.
     *
     * @param array<string, list<string>> $extensions
     *
     * @api
     */
    public function withExtensions(array $extensions): self
    {
        return new self(
            oid: $this->oid,
            names: $this->names,
            type: $this->type,
            superClassOids: $this->superClassOids,
            must: $this->must,
            may: $this->may,
            desc: $this->desc,
            obsolete: $this->obsolete,
            extensions: $extensions,
        );
    }

    /**
     * Produces the description string used in the subschema objectClasses attribute.
     */
    public function toDescriptionString(): string
    {
        $parts = array_filter([
            '( ' . $this->oid,
            $this->token(
                DefinitionKeyword::NAME,
                $this->names !== []
                    ? $this->formatDescriptors($this->names)
                    : null,
            ),
            $this->token(
                DefinitionKeyword::DESC,
                $this->desc !== null
                    ? $this->quoteString($this->desc)
                    : null,
            ),
            $this->flag(
                DefinitionKeyword::OBSOLETE,
                $this->obsolete,
            ),
            $this->token(
                DefinitionKeyword::SUP,
                $this->superClassOids !== []
                    ? $this->formatOids($this->superClassOids)
                    : null,
            ),
            $this->type->value,
            $this->token(
                DefinitionKeyword::MUST,
                $this->must !== []
                    ? $this->formatOids($this->must)
                    : null,
            ),
            $this->token(
                DefinitionKeyword::MAY,
                $this->may !== []
                    ? $this->formatOids($this->may)
                    : null,
            ),
        ]);

        foreach ($this->extensions as $name => $values) {
            $parts[] = $name . ' ' . $this->formatDescriptors($values);
        }

        return implode(' ', $parts) . ' )';
    }
}
