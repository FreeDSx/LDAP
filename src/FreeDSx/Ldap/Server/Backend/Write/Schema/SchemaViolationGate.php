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

namespace FreeDSx\Ldap\Server\Backend\Write\Schema;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Exception\SchemaValidationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedAttributeTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Decides whether a write proceeds: each schema violation by the rule it breaks, and backend limits nothing waives.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaViolationGate
{
    use DerivedAttributeTrait;

    public function __construct(
        private SchemaValidator $validator,
        private LinkedAttributes $linked,
    ) {}

    /**
     * @throws OperationException
     */
    public function assertAddAllowed(
        Entry $entry,
        WriteContext $context,
    ): void {
        $this->assertAllowed(
            SchemaWrite::add(
                $entry,
                $context->isSystem(),
            ),
            $context,
        );
    }

    /**
     * @throws OperationException
     */
    public function assertModifyAllowed(
        UpdateCommand $command,
        Entry $updated,
        WriteContext $context,
    ): void {
        $this->assertAllowed(
            SchemaWrite::modify(
                $updated,
                $command->changes,
                $context->isSystem(),
            ),
            $context,
        );
    }

    /**
     * @throws OperationException
     */
    public function assertMoveAllowed(
        Entry $moved,
        WriteContext $context,
    ): void {
        $this->assertAllowed(
            SchemaWrite::modifyDn(
                $moved,
                $context->isSystem(),
            ),
            $context,
        );
    }

    /**
     * @throws OperationException
     */
    private function assertAllowed(
        SchemaWrite $write,
        WriteContext $context,
    ): void {
        $this->assertTypesStorable($write->entry);
        $this->assertServerOwnedUntouched($write);

        try {
            $this->validator->validate($write);
        } catch (SchemaValidationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function assertTypesStorable(Entry $entry): void
    {
        foreach ($entry->getAttributes() as $attribute) {
            $type = $attribute->getName();

            // RFC 4512 2.5: a description always names a type, whatever the validation mode allows.
            if ($type === '') {
                throw new OperationException(
                    'The attribute description names no attribute type.',
                    ResultCode::UNDEFINED_ATTRIBUTE_TYPE,
                );
            }
            if (Attribute::isStorableType($type)) {
                continue;
            }

            throw new OperationException(
                sprintf(
                    'The attribute type is %d bytes, beyond the %d the directory stores, or is not ASCII.',
                    strlen($type),
                    Attribute::MAX_TYPE_LENGTH,
                ),
                ResultCode::ADMIN_LIMIT_EXCEEDED,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function assertServerOwnedUntouched(SchemaWrite $write): void
    {
        foreach ($write->suppliedNames() as $name) {
            if (!$this->isServerOwned($name, $write->operation)) {
                continue;
            }

            throw new OperationException(
                sprintf(
                    'The attribute "%s" is maintained by the server and cannot be written.',
                    $name,
                ),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
    }

    /**
     * An Add may still supply its entryUUID, since that is where an entry's identity begins.
     */
    private function isServerOwned(
        string $name,
        OperationType $operation,
    ): bool {
        if ($operation !== OperationType::Add && self::namesEntryUuid($name)) {
            return true;
        }

        return self::describesAnyDerivedAttribute($name)
            || $this->linked->linkedBy($name) !== null;
    }

    private static function namesEntryUuid(string $name): bool
    {
        return Attribute::normalizeName($name) === strtolower(AttributeTypeOid::NAME_ENTRY_UUID);
    }

    /**
     * @throws SchemaRuleException
     */
    private function recordOrReject(
        SchemaValidationException $validation,
        WriteContext $context,
    ): void {
        $rejected = null;

        foreach ($validation->violations as $violation) {
            $disposition = $this->dispositionFor(
                $violation,
                $context,
            );
            $context->schemaViolations()->record(
                $violation,
                $disposition,
            );

            if ($disposition === SchemaViolationDisposition::Rejected) {
                $rejected ??= $violation;
            }
        }

        if ($rejected !== null) {
            throw new SchemaRuleException(
                $rejected,
                $context->schemaViolations(),
            );
        }
    }

    private function dispositionFor(
        RuleViolation $violation,
        WriteContext $context,
    ): SchemaViolationDisposition {
        if ($violation->rule->isRelaxableByControl() && $context->getControls()->has(Control::OID_RELAX_RULES)) {
            return SchemaViolationDisposition::RelaxedByControl;
        }

        if ($violation->rule->isRelaxableByPolicy() && $this->isLenient($context)) {
            return SchemaViolationDisposition::RelaxedByPolicy;
        }

        return SchemaViolationDisposition::Rejected;
    }

    private function isLenient(WriteContext $context): bool
    {
        return $this->validator->mode() === SchemaValidationMode::Lenient
            || $context->bulkLoadOptions()?->ignoreValidation === true;
    }
}
