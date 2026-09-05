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

use Throwable;

/**
 * A failure no result code can answer which ends the session (RFC 4511 §4.1.1).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface UnrecoverableExceptionInterface extends Throwable {}
