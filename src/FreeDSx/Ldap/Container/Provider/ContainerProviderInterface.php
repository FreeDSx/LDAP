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

namespace FreeDSx\Ldap\Container\Provider;

use FreeDSx\Ldap\Container;

/**
 * Supplies a focused set of container factories, merged into the container at construction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ContainerProviderInterface
{
    /**
     * @return array<class-string, callable(Container): object> factory map keyed by the class each factory produces.
     */
    public function factories(): array;
}
