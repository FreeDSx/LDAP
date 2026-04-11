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

namespace FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;

/**
 * Marker interface for backends that support all LDAP write operations.
 *
 * Implementing this interface signals full CRUD capability. The optional
 * WritableBackendTrait bridges the WriteHandlerInterface contract (supports()
 * and handle()) to four typed methods (add, delete, update, move), which is
 * the recommended approach for full-CRUD backends.
 *
 * For partial write support — where a backend or standalone class handles only
 * a subset of write operations — implement WriteHandlerInterface directly and
 * register the handler via LdapServer::useWriteHandler().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WritableLdapBackendInterface extends LdapBackendInterface, WriteHandlerInterface {}
