<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap\Server\Process\Channel;

use FreeDSx\Ldap\Server\Process\Channel\ChannelMessage;
use FreeDSx\Ldap\Server\Process\Channel\ChannelMessageFactory;

final class FakeChannelMessageFactory implements ChannelMessageFactory
{
    /**
     * @param array<array-key, mixed> $data
     */
    public function fromArray(array $data): ChannelMessage
    {
        /** @var array<string, mixed> $data */
        return new FakeChannelMessage($data);
    }
}
