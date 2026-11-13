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
 * A request the server decoded but has no room to hold, answered by its ID as one that failed to decode would be.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestRefusedException extends MessageDecodeException {}
