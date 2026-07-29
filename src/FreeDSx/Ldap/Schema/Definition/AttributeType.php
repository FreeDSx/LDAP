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
 * An attribute type definition per RFC 4512 §4.1.2.
 */
final readonly class AttributeType
{
    use DefinitionStringTrait;

    /**
     * Marks values readable only by a subject holding a confidential-access grant; RFC 4512 §4.1 vendor extension.
     */
    public const EXTENSION_CONFIDENTIAL = 'X-CONFIDENTIAL';

    /**
     * The value an extension carries when it is set; extension values are qdstrings, not booleans.
     */
    public const EXTENSION_ENABLED_VALUE = 'TRUE';

    /**
     * @param list<string> $names
     * @param array<string, list<string>> $extensions
     */
    public function __construct(
        public string $oid,
        public array $names,
        public ?string $equalityOid = null,
        public ?string $orderingOid = null,
        public ?string $substringOid = null,
        public ?string $syntaxOid = null,
        public bool $singleValue = false,
        public bool $collective = false,
        public bool $noUserModification = false,
        public AttributeUsage $usage = AttributeUsage::UserApplications,
        public ?string $superTypeOid = null,
        public ?string $desc = null,
        public bool $obsolete = false,
        public array $extensions = [],
    ) {}

    /**
     * Whether values are withheld from anyone without a confidential-access grant, in results and in filters.
     */
    public function isConfidential(): bool
    {
        return in_array(
            self::EXTENSION_ENABLED_VALUE,
            $this->extensions[self::EXTENSION_CONFIDENTIAL] ?? [],
            true,
        );
    }

    /**
     * Produces the description string used in the subschema attributeTypes attribute.
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
                $this->superTypeOid,
            ),
            $this->token(
                DefinitionKeyword::EQUALITY,
                $this->equalityOid,
            ),
            $this->token(
                DefinitionKeyword::ORDERING,
                $this->orderingOid,
            ),
            $this->token(
                DefinitionKeyword::SUBSTR,
                $this->substringOid,
            ),
            $this->token(
                DefinitionKeyword::SYNTAX,
                $this->syntaxOid,
            ),
            $this->flag(
                DefinitionKeyword::SINGLE_VALUE,
                $this->singleValue,
            ),
            $this->flag(
                DefinitionKeyword::COLLECTIVE,
                $this->collective,
            ),
            $this->flag(
                DefinitionKeyword::NO_USER_MODIFICATION,
                $this->noUserModification,
            ),
            $this->token(
                DefinitionKeyword::USAGE,
                $this->usage !== AttributeUsage::UserApplications
                    ? $this->usage->value
                    : null,
            ),
        ]);

        foreach ($this->extensions as $name => $values) {
            $parts[] = $name . ' ' . $this->formatDescriptors($values);
        }

        return implode(' ', $parts) . ' )';
    }
}
