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
use function strcasecmp;

/**
 * RFC 4512 2.4.2: the structural object class of an entry shall not be changed.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class StructuralClassChangeCheck implements SchemaCheckInterface
{
    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        // An add sets the structural class, and a rename keeps the object classes it had.
        if ($write->operation !== OperationType::Modify) {
            return [];
        }

        $recorded = $write->entry->get('structuralObjectClass')?->firstValue();
        $structural = $classes->structuralHead?->names[0] ?? null;

        if ($recorded === null || $structural === null || strcasecmp($structural, $recorded) === 0) {
            return [];
        }

        return [
            new RuleViolation(
                SchemaRule::StructuralClassChange,
                ResultCode::OBJECT_CLASS_MODS_PROHIBITED,
                sprintf(
                    'The structural object class cannot be changed from "%s" to "%s".',
                    $recorded,
                    $structural,
                ),
            ),
        ];
    }
}
