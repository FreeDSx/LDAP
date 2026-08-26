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

namespace FreeDSx\Ldap\Server\Backend\Write\Replay;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Token\SystemToken;

/**
 * Replays parsed change records through the server's request pipeline as system-initiated operations.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WriteRequestReplayer
{
    public function __construct(private MiddlewareHandlerInterface $pipeline) {}

    /**
     * @param iterable<LdifChangeRecord> $records
     * @throws OperationException
     */
    public function apply(iterable $records): void
    {
        $messageId = 0;

        foreach ($records as $record) {
            ++$messageId;

            $this->assertApplied($this->pipeline->handle(new ServerRequestContext(
                new LdapMessageRequest(
                    $messageId,
                    $record->request,
                    ...$record->controls,
                ),
                new SystemToken(),
            )));
        }
    }

    /**
     * A refusal answered as a response rather than thrown has no client to read it here, so it is raised instead.
     *
     * @throws OperationException
     */
    private function assertApplied(ResponseStream $stream): void
    {
        $result = $stream->outcome();

        if ($result->outcome() === OperationOutcome::Succeeded) {
            return;
        }

        throw new OperationException(
            'The change record was refused by the server.',
            $result->resultCode(),
        );
    }
}
