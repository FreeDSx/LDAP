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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Applies attribute changes (ADD / DELETE / REPLACE) to an Entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class UpdateOperation
{
    /**
     * @throws OperationException
     */
    public function execute(
        Entry $entry,
        UpdateCommand $command,
    ): Entry {
        foreach ($command->changes as $change) {
            match ($change->getType()) {
                Change::TYPE_ADD => $this->applyAdd($entry, $change),
                Change::TYPE_DELETE => $this->applyDelete($entry, $change),
                Change::TYPE_REPLACE => $this->applyReplace($entry, $change),
                default => throw new OperationException(
                    sprintf('Unknown modify change type: %d.', $change->getType()),
                    ResultCode::PROTOCOL_ERROR,
                ),
            };
        }

        return $entry;
    }

    private function applyAdd(
        Entry $entry,
        Change $change
    ): void {
        $attribute = $change->getAttribute();
        $attrName = $attribute->getName();
        $existing = $entry->get($attrName);

        if ($existing === null) {
            $entry->add($attribute);
            return;
        }

        foreach ($attribute->getValues() as $value) {
            if ($existing->has($value)) {
                throw new OperationException(
                    sprintf('Attribute "%s" already contains the value "%s".', $attrName, $value),
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                );
            }
        }

        $existing->add(...$attribute->getValues());
    }

    /**
     * @throws OperationException
     */
    private function applyDelete(
        Entry $entry,
        Change $change
    ): void {
        $attrName = $change->getAttribute()->getName();
        $values = $change->getAttribute()->getValues();

        if (count($values) === 0) {
            $this->deleteWholeAttribute($entry, $attrName);
            return;
        }

        $this->deleteSpecificValues($entry, $attrName, $values);
    }

    /**
     * @throws OperationException
     */
    private function deleteWholeAttribute(
        Entry $entry,
        string $attrName
    ): void {
        if ($entry->get($attrName) === null) {
            throw new OperationException(
                sprintf('Attribute "%s" does not exist.', $attrName),
                ResultCode::NO_SUCH_ATTRIBUTE,
            );
        }

        if ($this->isRdnAttribute($entry, $attrName)) {
            throw new OperationException(
                sprintf('Attribute "%s" is the RDN attribute and cannot be removed.', $attrName),
                ResultCode::NOT_ALLOWED_ON_RDN,
            );
        }

        $entry->reset($attrName);
    }

    /**
     * @param string[] $values
     *
     * @throws OperationException
     */
    private function deleteSpecificValues(
        Entry $entry,
        string $attrName,
        array $values,
    ): void {
        $existing = $entry->get($attrName);

        if ($existing === null) {
            throw new OperationException(
                sprintf('Attribute "%s" does not exist.', $attrName),
                ResultCode::NO_SUCH_ATTRIBUTE,
            );
        }

        $rdnValue = $entry->getDn()->getRdn()->getValue();

        foreach ($values as $value) {
            if (!$existing->has($value)) {
                throw new OperationException(
                    sprintf('Value "%s" does not exist in attribute "%s".', $value, $attrName),
                    ResultCode::NO_SUCH_ATTRIBUTE,
                );
            }

            if ($this->isRdnAttribute($entry, $attrName) && $value === $rdnValue) {
                throw new OperationException(
                    sprintf(
                        'Value "%s" is the RDN value for attribute "%s" and cannot be removed.',
                        $value,
                        $attrName,
                    ),
                    ResultCode::NOT_ALLOWED_ON_RDN,
                );
            }
        }

        $existing->remove(...$values);
    }

    /**
     * @throws OperationException
     */
    private function applyReplace(Entry $entry, Change $change): void
    {
        $attribute = $change->getAttribute();
        $attrName = $attribute->getName();
        $values = $attribute->getValues();

        if (count($values) === 0) {
            $this->clearAttribute(
                $entry,
                $attrName
            );

            return;
        }

        $rdnValue = $entry->getDn()->getRdn()->getValue();

        if ($this->isRdnAttribute($entry, $attrName) && !in_array($rdnValue, $values, true)) {
            throw new OperationException(
                sprintf(
                    'Replacing attribute "%s" must retain the RDN value "%s".',
                    $attrName,
                    $rdnValue,
                ),
                ResultCode::NOT_ALLOWED_ON_RDN,
            );
        }

        $entry->set($attribute);
    }

    /**
     * @throws OperationException
     */
    private function clearAttribute(
        Entry $entry,
        string $attrName
    ): void {
        if ($this->isRdnAttribute($entry, $attrName)) {
            throw new OperationException(
                sprintf('Attribute "%s" is the RDN attribute and cannot be cleared.', $attrName),
                ResultCode::NOT_ALLOWED_ON_RDN,
            );
        }

        $entry->reset($attrName);
    }

    private function isRdnAttribute(
        Entry $entry,
        string $attrName
    ): bool {
        return strcasecmp(
            $entry->getDn()->getRdn()->getName(),
            $attrName
        ) === 0;
    }
}
