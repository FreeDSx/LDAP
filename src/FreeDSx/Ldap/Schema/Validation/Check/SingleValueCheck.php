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
 * RFC 4512 4.1.2: a SINGLE-VALUE attribute may hold only one value.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class SingleValueCheck implements SchemaCheckInterface
{
    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        foreach ($write->valueCounts() as $name => $count) {
            $attrType = $this->schema->getAttributeType($name);

            if ($attrType === null || !$attrType->singleValue || $count <= 1) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::SingleValue,
                    ResultCode::CONSTRAINT_VIOLATION,
                    sprintf(
                        'Attribute "%s" is single-valued but has more than one value.',
                        $attrType->primaryName(),
                    ),
                ),
            ];
        }

        return [];
    }
}
