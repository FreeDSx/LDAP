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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;

/**
 * Returns a minimal stub subschema entry, satisfying clients that follow up on the subschemaSubentry DN advertised in the RootDSE.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSubschemaHandler implements ServerProtocolHandlerInterface
{
    public function __construct(
        private readonly ServerOptions $options,
        private readonly ServerQueue $queue,
    ) {
    }

    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): void {
        $schemaDn = $this->options->getSubschemaEntry();
        $rdn = $schemaDn->getRdn();

        $entry = Entry::fromArray($schemaDn->toString(), [
            'objectClass'    => ['top', 'subschema'],
            $rdn->getName()  => [$rdn->getValue()],
        ]);

        $this->queue->sendMessage(
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry),
            ),
            new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultDone(ResultCode::SUCCESS),
            ),
        );
    }
}
