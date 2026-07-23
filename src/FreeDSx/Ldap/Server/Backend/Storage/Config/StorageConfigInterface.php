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

namespace FreeDSx\Ldap\Server\Backend\Storage\Config;

/**
 * Configures the storage backend for the server; pass one to ServerOptions::setStorage().
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface StorageConfigInterface
{
    /**
     * The storage backend this config selects.
     */
    public function type(): StorageType;
}
