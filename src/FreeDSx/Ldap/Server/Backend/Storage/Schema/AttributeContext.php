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

namespace FreeDSx\Ldap\Server\Backend\Storage\Schema;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Definition\MatchingRuleOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\AttributeFilterSupport;

/**
 * Answers the storage layer's attribute questions from the configured schema.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AttributeContext implements AttributeContextInterface
{
    use DerivedAttributeTrait;

    public function __construct(
        private Schema $schema,
        private AttributeSyntaxResolver $syntax,
    ) {}

    public function assertionValueConforms(
        string $attribute,
        string $value,
    ): bool {
        return $this->syntax->conforms(
            $attribute,
            $value,
        );
    }

    public function hasSubstringRule(string $attribute): bool
    {
        // Options are not part of the type, so they are dropped before asking the schema about it.
        return $this->schema->getSubstringRuleOid(Attribute::normalizeName($attribute)) !== null;
    }

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

        // Options are not part of the type, so they are dropped before asking the schema about it.
        $type = Attribute::normalizeName($attribute);
        if ($this->schema->getAttributeType($type) === null) {
            return AttributeFilterSupport::NeverMatches;
        }

        return $this->schema->hasSubtypes($type)
            ? AttributeFilterSupport::NeedsEvaluator
            : AttributeFilterSupport::Exact;
    }

    public function isIntegerOrdered(string $attribute): ?bool
    {
        return $this->schema->isIntegerOrdered($attribute);
    }

    public function isCaseInsensitive(string $attribute): ?bool
    {
        return $this->schema->isCaseInsensitiveMatched($attribute);
    }

    public function oidSpellings(
        string $attribute,
        string $value,
    ): ?array {
        // Options are not part of the type, so they are dropped before asking the schema about it.
        $equalityOid = $this->schema
            ->getAttributeType(Attribute::normalizeName($attribute))
            ?->equalityOid;

        return $equalityOid === MatchingRuleOid::OID_OBJECT_IDENTIFIER_MATCH
            ? $this->schema->oidSpellings($value)
            : null;
    }
}
