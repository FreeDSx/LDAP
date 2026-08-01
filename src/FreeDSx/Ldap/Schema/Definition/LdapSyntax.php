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
 * An LDAP syntax definition per RFC 4512 §4.1.5.
 */
final readonly class LdapSyntax
{
    use DefinitionStringTrait;

    /**
     * @param array<string, list<string>> $extensions
     */
    public function __construct(
        public string $oid,
        public ?string $desc = null,
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
            desc: $this->desc,
            extensions: $extensions,
        );
    }

    /**
     * Produces the description string used in the subschema ldapSyntaxes attribute.
     */
    public function toDescriptionString(): string
    {
        $parts = array_filter([
            '( ' . $this->oid,
            $this->token(
                DefinitionKeyword::DESC,
                $this->desc !== null
                    ? $this->quoteString($this->desc)
                    : null,
            ),
        ]);

        foreach ($this->extensions as $name => $values) {
            $parts[] = $name . ' ' . $this->formatDescriptors($values);
        }

        return implode(' ', $parts) . ' )';
    }
}
