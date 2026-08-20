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

namespace FreeDSx\Ldap\Schema\Validation\Syntax;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Answers whether a value conforms to the syntax an attribute type carries, following the SUP chain to find it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AttributeSyntaxResolver
{
    private SyntaxValidatorRegistry $registry;

    public function __construct(private Schema $schema)
    {
        $this->registry = SyntaxValidatorRegistry::default();
    }

    /**
     * Whether a value conforms; true when the type is unknown or its syntax carries no validator.
     */
    public function conforms(
        string $attributeDescription,
        string $value,
    ): bool {
        $type = $this->schema->getAttributeType(Attribute::normalizeName($attributeDescription));

        if ($type === null) {
            return true;
        }

        return $this->validatorFor($type)?->isValid($value) ?? true;
    }

    /**
     * The validator enforcing the type's effective syntax, or null when it is unconstrained.
     */
    public function validatorFor(AttributeType $type): ?SyntaxValidatorInterface
    {
        $syntaxOid = $this->schema->getSyntaxOid($type->oid);

        return $syntaxOid === null
            ? null
            : $this->registry->get($syntaxOid);
    }
}
