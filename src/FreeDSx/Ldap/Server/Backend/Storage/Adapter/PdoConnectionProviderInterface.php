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

use PDO;

/**
 * Resolves a PDO connection and its transaction state for the current execution context.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoConnectionProviderInterface
{
    public function get(): PDO;

    public function txState(): PdoTxState;
}
