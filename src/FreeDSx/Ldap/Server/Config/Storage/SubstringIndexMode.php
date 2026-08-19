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

namespace FreeDSx\Ldap\Server\Config\Storage;

/**
 * The index a PdoStorage maintains to narrow substring filters; the container resolves it to an implementation.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
enum SubstringIndexMode
{
    /**
     * The best index the driver supports: FTS5 on SQLite where the build provides it, otherwise trigram.
     */
    case Auto;

    /**
     * The portable trigram table, supported by every driver.
     */
    case Trigram;

    /**
     * No index; substring filters scan.
     */
    case None;
}
