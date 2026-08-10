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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Projects an entry onto a search request's attribute selection list (RFC 4511 §4.5.1.8, RFC 3673).
 *
 *   - empty list / "*" = all user attributes; operational ones only when also named
 *   - "+"              = all operational attributes (classified via the supplied schema)
 *   - "1.1"            = no attributes (DN only)
 *   - explicit names   = only those, whatever their usage
 *
 * An attribute the schema does not define counts as a user attribute, so unknown ones keep flowing.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AttributeProjection
{
    /**
     * Per-instance memo of operational classification keyed on lowercased attribute name.
     *
     * @var array<string, bool>
     */
    private array $operationalByName = [];

    /**
     * @param string[] $names
     */
    private function __construct(
        private readonly array $names,
        private readonly bool $wantsUser,
        private readonly bool $wantsOperational,
        private readonly bool $returnNone,
        private readonly bool $typesOnly,
        private readonly Schema $schema,
    ) {}

    /**
     * @param Attribute[] $requestedAttrs
     */
    public static function forRequest(
        array $requestedAttrs,
        bool $typesOnly,
        Schema $schema,
    ): self {
        $names = array_map(
            static fn(Attribute $a): string => strtolower($a->getDescription()),
            $requestedAttrs,
        );

        return new self(
            $names,
            count($names) === 0 || in_array('*', $names, true),
            in_array('+', $names, true),
            count($names) === 1 && $names[0] === '1.1',
            $typesOnly,
            $schema,
        );
    }

    public function project(Entry $entry): Entry
    {
        $filteredAttributes = [];

        if (!$this->returnNone) {
            foreach ($entry->getAttributes() as $attribute) {
                if (!$this->shouldInclude($attribute)) {
                    continue;
                }

                $filteredAttributes[] = $this->typesOnly
                    ? new Attribute($attribute->getName())
                    : $attribute;
            }
        }

        return Entry::raw(
            $entry->getDn(),
            $filteredAttributes,
        );
    }

    private function shouldInclude(Attribute $attribute): bool
    {
        if (in_array(strtolower($attribute->getDescription()), $this->names, true)) {
            return true;
        }

        return $this->isOperational($attribute)
            ? $this->wantsOperational
            : $this->wantsUser;
    }

    private function isOperational(Attribute $attribute): bool
    {
        $key = strtolower($attribute->getName());

        if (isset($this->operationalByName[$key])) {
            return $this->operationalByName[$key];
        }

        $type = $this->schema->getAttributeType($attribute->getName());

        return $this->operationalByName[$key] = $type !== null
            && $type->usage !== AttributeUsage::UserApplications;
    }
}
