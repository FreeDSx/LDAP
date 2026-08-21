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
 * Represents a URL-referenced LDIF value that could not be resolved.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class LdifUrlException extends Exception {}
