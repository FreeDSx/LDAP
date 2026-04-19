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
 * Marker for full-CRUD backends; pair with WritableBackendTrait for typed add/delete/update/move methods. For partial
 * write support, implement WriteHandlerInterface directly and register via LdapServer::useWriteHandler().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WritableLdapBackendInterface extends LdapBackendInterface, WriteHandlerInterface {}
