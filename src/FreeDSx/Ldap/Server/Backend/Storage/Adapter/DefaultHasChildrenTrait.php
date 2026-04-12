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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;

/**
 * Provides a default hasChildren() implementation in terms of list().
 *
 * Suitable for any EntryStorageInterface implementation. Adapters that can
 * answer the question more efficiently (e.g. via an EXISTS query on a database)
 * should override hasChildren() directly.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait DefaultHasChildrenTrait
{
    abstract public function list(StorageListOptions $options): EntryStream;

    public function hasChildren(Dn $dn): bool
    {
        foreach ($this->list(StorageListOptions::matchAll(baseDn: $dn, subtree: false))->entries as $ignored) {
            return true;
        }

        return false;
    }
}
