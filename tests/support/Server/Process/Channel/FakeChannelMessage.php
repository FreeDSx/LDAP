<?php

declare(strict_types=1);

namespace Tests\Support\FreeDSx\Ldap\Server\Process\Channel;

use FreeDSx\Ldap\Server\Process\Channel\ChannelMessage;

final readonly class FakeChannelMessage implements ChannelMessage
{
    /**
     * @param array<string, mixed> $payload
     */
    public function __construct(private array $payload) {}

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return $this->payload;
    }
}
