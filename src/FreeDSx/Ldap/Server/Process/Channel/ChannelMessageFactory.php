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

namespace FreeDSx\Ldap\Server\Process\Channel;

/**
 * Reconstructs a ChannelMessage from its wire form on the receiving end of a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChannelMessageFactory
{
    /**
     * @param array<array-key, mixed> $data
     */
    public function fromArray(array $data): ChannelMessage;
}
