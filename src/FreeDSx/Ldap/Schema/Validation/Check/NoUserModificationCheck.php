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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function array_map;
use function in_array;
use function sprintf;

/**
 * RFC 4512 4.1.2: a client may not supply a NO-USER-MODIFICATION attribute.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class NoUserModificationCheck implements SchemaCheckInterface
{
    /**
     * The operational attributes draft-zeilenga-ldap-relax §3.6 lets a relaxed Add supply.
     */
    private const SETTABLE_ON_ADD = [
        AttributeTypeOid::NAME_ENTRY_UUID,
        AttributeTypeOid::NAME_CREATE_TIMESTAMP,
        AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
        AttributeTypeOid::NAME_CREATORS_NAME,
        AttributeTypeOid::NAME_MODIFIERS_NAME,
    ];

    /**
     * The same on Modify less entryUUID, which replication and the password policy forward address an entry by.
     */
    private const SETTABLE_ON_MODIFY = [
        AttributeTypeOid::NAME_CREATE_TIMESTAMP,
        AttributeTypeOid::NAME_MODIFY_TIMESTAMP,
        AttributeTypeOid::NAME_CREATORS_NAME,
        AttributeTypeOid::NAME_MODIFIERS_NAME,
    ];

    public function __construct(private Schema $schema) {}

    /**
     * Each rule is reported apart, so a settable attribute the Relax control waives cannot hide one it does not.
     */
    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        if ($write->isSystem) {
            return [];
        }

        $violations = [];

        foreach ([SchemaRule::NoUserModification, SchemaRule::SettableOperationalAttribute] as $rule) {
            $name = $this->firstSuppliedUnder(
                $rule,
                $write,
            );

            if ($name === null) {
                continue;
            }

            $violations[] = new RuleViolation(
                $rule,
                ResultCode::CONSTRAINT_VIOLATION,
                sprintf(
                    $write->operation === OperationType::Modify
                        ? 'Attribute "%s" cannot be modified by users.'
                        : 'Attribute "%s" cannot be set by users.',
                    $name,
                ),
            );
        }

        return $violations;
    }

    /**
     * The first NO-USER-MODIFICATION attribute the write supplies that falls under the given rule.
     */
    private function firstSuppliedUnder(
        SchemaRule $rule,
        SchemaWrite $write,
    ): ?string {
        $wantSettable = $rule === SchemaRule::SettableOperationalAttribute;
        $settable = $this->settableOn($write->operation);

        foreach ($this->suppliedNames($write) as $name) {
            $attrType = $this->schema->getAttributeType($name);

            if ($attrType === null || !$attrType->noUserModification) {
                continue;
            }
            if (in_array($attrType->primaryName(), $settable, true) !== $wantSettable) {
                continue;
            }

            return $name;
        }

        return null;
    }

    /**
     * @return array<string>
     */
    private function suppliedNames(SchemaWrite $write): array
    {
        return match ($write->operation) {
            OperationType::Add => array_map(
                static fn(Attribute $attribute): string => $attribute->getName(),
                $write->entry->getAttributes(),
            ),
            OperationType::Modify => array_map(
                static fn(Change $change): string => $change->getAttribute()->getName(),
                $write->changes,
            ),
            // A rename supplies only the values its new RDN puts on the entry.
            default => array_map(
                static fn(Rdn $component): string => $component->getName(),
                $write->entry->getDn()->getRdn()->getAll(),
            ),
        };
    }

    /**
     * @return list<string>
     */
    private function settableOn(OperationType $operation): array
    {
        return match ($operation) {
            OperationType::Add => self::SETTABLE_ON_ADD,
            OperationType::Modify => self::SETTABLE_ON_MODIFY,
            default => [],
        };
    }
}
