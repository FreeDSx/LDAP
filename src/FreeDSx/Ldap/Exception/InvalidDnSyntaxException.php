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

namespace FreeDSx\Ldap\Exception;

/**
 * Thrown when a DN or RDN cannot be parsed, so a client-supplied one can be answered with invalidDNSyntax.
 */
class InvalidDnSyntaxException extends InvalidArgumentException {}
