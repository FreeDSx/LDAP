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

use Exception;

/**
 * Thrown in the sync handler to indicate that the sync operation should be canceled.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class CancelSyncException extends Exception
{
}
