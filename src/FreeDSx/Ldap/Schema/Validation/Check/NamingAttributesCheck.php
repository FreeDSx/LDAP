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

namespace FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;

/**
 * RFC 4512 2.5.1: a type specifying no equality matching cannot be used for naming.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class NamingAttributesCheck implements SchemaCheckInterface
{
    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        $dn = $write->entry->getDn();

        if (!$write->namesEntry() || $dn->isRootDse()) {
            return [];
        }

        foreach ($dn->getRdn()->getAll() as $component) {
            $attrType = $this->schema->getAttributeType($component->getName());
            // An undefined type is reported by its own check, which says something more useful about it.
            if ($attrType === null || $this->schema->getEqualityRuleOid($attrType->oid) !== null) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::NamingAttributes,
                    ResultCode::NAMING_VIOLATION,
                    sprintf(
                        'Attribute "%s" has no equality matching rule and cannot name an entry.',
                        $component->getName(),
                    ),
                ),
            ];
        }

        return [];
    }
}
