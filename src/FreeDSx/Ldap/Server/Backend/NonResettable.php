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
 * Stands in for a component that holds nothing worth discarding, so a resettable is never absent.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class NonResettable implements ResettableInterface
{
    public function reset(): void {}
}
