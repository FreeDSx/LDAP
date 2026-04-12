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

namespace FreeDSx\Ldap\Server\Backend\Storage\Exception;

use FreeDSx\Ldap\Exception\RuntimeException;

/**
 * Thrown by a storage adapter when a filter contains an attribute name that does not conform to the RFC 4512 attribute
 * description syntax.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class InvalidAttributeException extends RuntimeException
{
}
