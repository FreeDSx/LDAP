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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\AttributeFilterSupport;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterAttributeContextInterface;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;

/**
 * DTO for EntryStorageInterface::list(), decoupled from LDAP protocol objects.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class StorageListOptions implements FilterAttributeContextInterface
{
    use DerivedAttributeTrait;

    private ?AttributeSyntaxResolver $syntaxResolver;

    /**
     * @param SortKey[] $sortKeys
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     * @param ?Schema $schema Answers the attribute questions below; callers with no schema leave it null.
     */
    public function __construct(
        public Dn $baseDn,
        public bool $subtree,
        public FilterInterface $filter,
        public int $timeLimit = 0,
        public int $sizeLimit = 0,
        public array $sortKeys = [],
        public int $lookthroughLimit = 0,
        public ?array $attributes = null,
        public SubentryVisibility $subentries = SubentryVisibility::All,
        public ?Schema $schema = null,
    ) {
        $this->syntaxResolver = $schema === null
            ? null
            : new AttributeSyntaxResolver($schema);
    }

    /**
     * Whether a value conforms to the attribute's syntax; true when no schema can say otherwise.
     */
    public function assertionValueConforms(
        string $attribute,
        string $value,
    ): bool {
        return $this->syntaxResolver?->conforms($attribute, $value) ?? true;
    }

    /**
     * Whether the attribute defines a SUBSTR rule; true when no schema can say otherwise.
     */
    public function hasSubstringRule(string $attribute): bool
    {
        if ($this->schema === null) {
            return true;
        }

        // Options are not part of the type, so they are dropped before asking the schema about it.
        return $this->schema->getSubstringRuleOid(Attribute::normalizeName($attribute)) !== null;
    }

    /**
     * How faithfully SQL alone can answer an assertion on the attribute.
     */
    public function filterSupport(string $attribute): AttributeFilterSupport
    {
        // Derived from the parent link, which SQL reads directly rather than needing a stored row.
        if (self::describesType($attribute, AttributeTypeOid::NAME_HAS_SUBORDINATES)) {
            return AttributeFilterSupport::Exact;
        }

        // Derived on read rather than stored, so no rows answer it and only the evaluator can.
        if (self::describesAnyDerivedAttribute($attribute)) {
            return AttributeFilterSupport::NeedsEvaluator;
        }

        if ($this->schema === null) {
            return AttributeFilterSupport::Exact;
        }

        // Options are not part of the type, so they are dropped before asking the schema about it.
        $type = Attribute::normalizeName($attribute);

        if ($this->schema->getAttributeType($type) === null) {
            return AttributeFilterSupport::NeverMatches;
        }

        return $this->schema->hasSubtypes($type)
            ? AttributeFilterSupport::NeedsEvaluator
            : AttributeFilterSupport::Exact;
    }

    /**
     * Whether the attribute orders numerically. null when unresolved (no schema was supplied).
     */
    public function isIntegerOrdered(string $attribute): ?bool
    {
        return $this->schema?->isIntegerOrdered($attribute);
    }

    /**
     * Whether the attribute matches without regard to case. null when unresolved (no schema was supplied).
     */
    public function isCaseInsensitive(string $attribute): ?bool
    {
        return $this->schema?->isCaseInsensitiveMatched($attribute);
    }

    /**
     * Match-all options for internal callers (e.g. hasChildren) and tests that do not need a meaningful filter.
     *
     * @param list<string>|null $attributes Lowercase base attribute names to materialize, or null for all.
     */
    public static function matchAll(
        Dn $baseDn,
        bool $subtree,
        int $timeLimit = 0,
        ?array $attributes = null,
    ): self {
        return new self(
            baseDn: $baseDn,
            subtree: $subtree,
            filter: new AndFilter(),
            timeLimit: $timeLimit,
            attributes: $attributes,
        );
    }
}
