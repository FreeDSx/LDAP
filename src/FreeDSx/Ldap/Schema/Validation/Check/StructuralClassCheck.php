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
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;

/**
 * RFC 4512 2.4.2: an entry belongs to exactly one structural object class chain.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class StructuralClassCheck implements SchemaCheckInterface
{
    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        if ($classes->structural === []) {
            return [
                $this->violation(
                    'Entry "%s" must have at least one structural object class.',
                    $write,
                ),
            ];
        }
        if ($classes->structuralHead !== null) {
            return [];
        }

        return [
            $this->violation(
                'Entry "%s" must not combine unrelated structural object classes.',
                $write,
            ),
        ];
    }

    private function violation(
        string $message,
        SchemaWrite $write,
    ): RuleViolation {
        return new RuleViolation(
            SchemaRule::StructuralClass,
            ResultCode::OBJECT_CLASS_VIOLATION,
            sprintf(
                $message,
                $write->entry->getDn()->toString(),
            ),
        );
    }
}
