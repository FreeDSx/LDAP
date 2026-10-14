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
 * RFC 4512 7.1: an entry may only belong to classes the schema defines.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DefinedObjectClassesCheck implements SchemaCheckInterface
{
    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        foreach ($write->entry->get('objectClass')?->getValues() ?? [] as $name) {
            if ($this->schema->getObjectClass($name) !== null) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::DefinedObjectClasses,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    sprintf(
                        'Undefined object class: "%s".',
                        $name,
                    ),
                ),
            ];
        }

        return [];
    }
}
