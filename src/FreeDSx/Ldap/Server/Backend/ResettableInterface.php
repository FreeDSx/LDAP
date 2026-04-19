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

namespace FreeDSx\Ldap\Server\Backend;

/**
 * Implemented by components whose cached state or connections should be discarded on demand (such as after forking).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ResettableInterface
{
    public function reset(): void;
}
