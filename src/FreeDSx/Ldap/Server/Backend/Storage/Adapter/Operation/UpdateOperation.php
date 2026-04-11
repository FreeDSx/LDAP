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
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;

/**
 * Applies attribute changes (ADD / DELETE / REPLACE) to an Entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class UpdateOperation
{
    public function execute(
        Entry $entry,
        UpdateCommand $command,
    ): Entry {
        foreach ($command->changes as $change) {
            $attribute = $change->getAttribute();
            $attrName = $attribute->getName();
            $values = $attribute->getValues();

            switch ($change->getType()) {
                case Change::TYPE_ADD:
                    $existing = $entry->get($attrName);
                    if ($existing !== null) {
                        $existing->add(...$values);
                    } else {
                        $entry->add($attribute);
                    }
                    break;

                case Change::TYPE_DELETE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->get($attrName)?->remove(...$values);
                    }
                    break;

                case Change::TYPE_REPLACE:
                    if (count($values) === 0) {
                        $entry->reset($attrName);
                    } else {
                        $entry->set($attribute);
                    }
                    break;
            }
        }

        return $entry;
    }
}
