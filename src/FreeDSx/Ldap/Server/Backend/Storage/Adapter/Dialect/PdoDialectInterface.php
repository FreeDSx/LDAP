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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoEntryListDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoEntryReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoEntryWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoJournalDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoPendingLinkDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoRowLockDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoSchemaDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoSidecarDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoTransactionDialectInterface;

/**
 * The full database-specific SQL the PDO storage needs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PdoDialectInterface extends
    PdoEntryListDialectInterface,
    PdoEntryReadDialectInterface,
    PdoEntryWriteDialectInterface,
    PdoJournalDialectInterface,
    PdoLinkReadDialectInterface,
    PdoLinkWriteDialectInterface,
    PdoPendingLinkDialectInterface,
    PdoRowLockDialectInterface,
    PdoSchemaDialectInterface,
    PdoSidecarDialectInterface,
    PdoTransactionDialectInterface {}
