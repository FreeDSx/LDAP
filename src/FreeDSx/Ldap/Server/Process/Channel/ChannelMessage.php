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
 * A message that can be sent between processes over a ChildChannel.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChannelMessage
{
    /**
     * @return array<string, mixed>
     */
    public function toArray(): array;
}
