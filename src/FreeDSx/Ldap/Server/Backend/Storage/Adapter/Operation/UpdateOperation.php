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

use FreeDSx\Ldap\Entry\Attribute;
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
        Change $change,
    ): void {
        $attribute = $change->getAttribute();

        // Legal to encode, but it would leave an attribute holding no values, which an entry cannot carry.
        if ($attribute->getValues() === []) {
            throw new OperationException(
                sprintf('The add of attribute "%s" requires values.', $attribute->getName()),
                ResultCode::PROTOCOL_ERROR,
            );
        }

        $existing = $entry->get($attribute, true);

        if ($existing === null) {
            $entry->add($attribute);
            return;
        }

        foreach ($attribute->getValues() as $value) {
            if ($existing->has($value, caseSensitive: false)) {
                throw new OperationException(
                    sprintf('Attribute "%s" already contains the given value.', $attribute->getName()),
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
        Change $change,
    ): void {
        $attribute = $change->getAttribute();
        $values = $attribute->getValues();

        if (count($values) === 0) {
            $this->deleteWholeAttribute($entry, $attribute);
            return;
        }

        $this->deleteSpecificValues($entry, $attribute, $values);
    }

    /**
     * @throws OperationException
     */
    private function deleteWholeAttribute(
        Entry $entry,
        Attribute $attribute,
    ): void {
        if ($entry->get($attribute, true) === null) {
            throw new OperationException(
                sprintf('Attribute "%s" does not exist.', $attribute->getName()),
                ResultCode::NO_SUCH_ATTRIBUTE,
            );
        }

        if ($this->isRdnAttribute($entry, $attribute->getName())) {
            throw new OperationException(
                sprintf('Attribute "%s" is the RDN attribute and cannot be removed.', $attribute->getName()),
                ResultCode::NOT_ALLOWED_ON_RDN,
            );
        }

        $entry->reset($attribute);
    }

    /**
     * @param string[] $values
     *
     * @throws OperationException
     */
    private function deleteSpecificValues(
        Entry $entry,
        Attribute $attribute,
        array $values,
    ): void {
        $existing = $entry->get($attribute, true);

        if ($existing === null) {
            throw new OperationException(
                sprintf('Attribute "%s" does not exist.', $attribute->getName()),
                ResultCode::NO_SUCH_ATTRIBUTE,
            );
        }

        $rdnValue = $this->getRdnValueForAttribute(
            $entry,
            $attribute->getName(),
        );

        foreach ($values as $value) {
            if (!$existing->has($value, caseSensitive: false)) {
                throw new OperationException(
                    sprintf('The given value does not exist in attribute "%s".', $attribute->getName()),
                    ResultCode::NO_SUCH_ATTRIBUTE,
                );
            }

            if ($rdnValue !== null && strcasecmp($value, $rdnValue) === 0) {
                throw new OperationException(
                    sprintf(
                        'The RDN value of attribute "%s" cannot be removed.',
                        $attribute->getName(),
                    ),
                    ResultCode::NOT_ALLOWED_ON_RDN,
                );
            }
        }

        $existing->removeValues(
            $values,
            caseSensitive: false,
        );
    }

    /**
     * @throws OperationException
     */
    private function applyReplace(Entry $entry, Change $change): void
    {
        $attribute = $change->getAttribute();
        $values = $attribute->getValues();

        if (count($values) === 0) {
            $this->clearAttribute(
                $entry,
                $attribute,
            );

            return;
        }

        $rdnValue = $this->getRdnValueForAttribute($entry, $attribute->getName());

        if ($rdnValue !== null && !$attribute->has($rdnValue, caseSensitive: false)) {
            throw new OperationException(
                sprintf(
                    'Replacing attribute "%s" must retain its RDN value.',
                    $attribute->getName(),
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
        Attribute $attribute,
    ): void {
        if ($this->isRdnAttribute($entry, $attribute->getName())) {
            throw new OperationException(
                sprintf('Attribute "%s" is the RDN attribute and cannot be cleared.', $attribute->getName()),
                ResultCode::NOT_ALLOWED_ON_RDN,
            );
        }

        $entry->reset($attribute);
    }

    private function isRdnAttribute(
        Entry $entry,
        string $attrName,
    ): bool {
        return $entry->getDn()
            ->getRdn()
            ->has($attrName);
    }

    private function getRdnValueForAttribute(
        Entry $entry,
        string $attrName,
    ): ?string {
        return $entry->getDn()
            ->getRdn()
            ->getValueOf($attrName);
    }
}
