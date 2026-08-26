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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Decides whether a schema violation stops the write, recording every one it sees either way.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SchemaViolationGate
{
    public function __construct(private SchemaValidator $validator) {}

    /**
     * @throws OperationException
     */
    public function assertAddAllowed(
        Entry $entry,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateAdd(
                $entry,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    public function assertModifyAllowed(
        UpdateCommand $command,
        Entry $updated,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateModify(
                $command,
                $updated,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    public function assertMoveAllowed(
        MoveCommand $command,
        Entry $moved,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateModifyDn(
                $moved,
                $command->newRdn,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * Records the violation for audit and rejects it, unless policy or the Relax control allows the write.
     *
     * @throws OperationException
     */
    private function recordOrReject(
        OperationException $violation,
        WriteContext $context,
    ): void {
        $disposition = $this->dispositionFor(
            $violation,
            $context,
        );
        $context->schemaViolations()->record(
            $violation,
            $disposition,
        );

        if ($disposition === SchemaViolationDisposition::Rejected) {
            throw new SchemaRuleException(
                $violation,
                $context->schemaViolations(),
            );
        }
    }

    private function dispositionFor(
        OperationException $violation,
        WriteContext $context,
    ): SchemaViolationDisposition {
        if ($violation->getCode() === ResultCode::INVALID_ATTRIBUTE_SYNTAX) {
            return SchemaViolationDisposition::Rejected;
        }

        if ($context->getControls()->has(Control::OID_RELAX_RULES)) {
            return SchemaViolationDisposition::RelaxedByControl;
        }

        return $this->validator->mode() === SchemaValidationMode::Lenient
            ? SchemaViolationDisposition::RelaxedByPolicy
            : SchemaViolationDisposition::Rejected;
    }
}
