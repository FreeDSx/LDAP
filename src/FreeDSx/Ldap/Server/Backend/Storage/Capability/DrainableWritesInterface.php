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

namespace FreeDSx\Ldap\Server\Backend\Storage\Capability;

/**
 * Storage that writes through a helper which outlives a single write.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface DrainableWritesInterface
{
    /**
     * Release the write helper now that no further write is coming, rather than leaving it to time out.
     *
     * For a caller that writes in one burst and then stops, such as seeding. Not for one still serving requests.
     */
    public function drainWrites(): void;
}
