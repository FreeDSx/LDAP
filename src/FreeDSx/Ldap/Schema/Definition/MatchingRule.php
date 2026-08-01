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

use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;

/**
 * A matching rule definition per RFC 4512 §4.1.3; carries its comparator strategy.
 */
final readonly class MatchingRule
{
    use DefinitionStringTrait;

    /**
     * @param list<string> $names
     * @param array<string, list<string>> $extensions
     */
    public function __construct(
        public string $oid,
        public array $names,
        public string $syntaxOid,
        public MatchingRuleComparatorInterface $comparator,
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
            syntaxOid: $this->syntaxOid,
            comparator: $this->comparator,
            desc: $this->desc,
            obsolete: $this->obsolete,
            extensions: $extensions,
        );
    }

    /**
     * Produces the matchingRuleUse description string for this rule and the attribute types that reference it.
     *
     * @param list<string> $appliesTo attribute type OIDs or names
     */
    public function toMatchingRuleUseString(array $appliesTo): string
    {
        $parts = array_filter([
            '( ' . $this->oid,
            $this->names !== []
                ? DefinitionKeyword::NAME . ' ' . $this->formatDescriptors($this->names)
                : null,
            $this->token(
                DefinitionKeyword::DESC,
                $this->desc !== null
                    ? $this->quoteString($this->desc)
                    : null,
            ),
            $this->obsolete
                ? DefinitionKeyword::OBSOLETE
                : null,
            DefinitionKeyword::APPLIES . ' ' . $this->formatOids($appliesTo),
        ]);

        return implode(' ', $parts) . ' )';
    }

    /**
     * Produces the description string used in the subschema matchingRules attribute.
     */
    public function toDescriptionString(): string
    {
        $parts = array_filter([
            '( ' . $this->oid,
            $this->names !== [] ? DefinitionKeyword::NAME . ' ' . $this->formatDescriptors($this->names) : null,
            $this->token(DefinitionKeyword::DESC, $this->desc !== null ? $this->quoteString($this->desc) : null),
            $this->obsolete ? DefinitionKeyword::OBSOLETE : null,
            DefinitionKeyword::SYNTAX . ' ' . $this->syntaxOid,
        ]);

        foreach ($this->extensions as $name => $values) {
            $parts[] = $name . ' ' . $this->formatDescriptors($values);
        }

        return implode(' ', $parts) . ' )';
    }
}
