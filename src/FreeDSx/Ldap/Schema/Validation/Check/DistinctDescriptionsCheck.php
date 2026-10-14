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

use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;
use function strtolower;

/**
 * RFC 4512 2.2: all attributes of an entry must have distinct attribute descriptions.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DistinctDescriptionsCheck implements SchemaCheckInterface
{
    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        // Only an add hands over the entry's attributes as the client listed them.
        if ($write->operation !== OperationType::Add) {
            return [];
        }

        $seen = [];

        foreach ($write->entry->getAttributes() as $attribute) {
            $description = strtolower($attribute->getDescription());

            if (isset($seen[$description])) {
                return [
                    new RuleViolation(
                        SchemaRule::DistinctDescriptions,
                        ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                        sprintf(
                            'Attribute "%s" is supplied more than once.',
                            $attribute->getDescription(),
                        ),
                    ),
                ];
            }

            $seen[$description] = true;
        }

        return [];
    }
}
