<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles search request logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSearchHandler implements ServerProtocolHandlerInterface
{
    /**
     * {@inheritDoc}
     */
    public function handleRequest(LdapMessageRequest $message, TokenInterface $token, RequestHandlerInterface $dispatcher, ServerQueue $queue, array $options): void
    {
        $context = new RequestContext($message->controls(), $token);
        $request = $message->getRequest();

        if (!$request instanceof SearchRequest) {
            throw new RuntimeException(sprintf(
                'Expected a search request, but got %s.',
                get_class($request)
            ));
        }
        $entries = $dispatcher->search($context, $request);

        $messages = [];
        foreach ($entries->toArray() as $entry) {
            $messages[] = new LdapMessageResponse(
                $message->getMessageId(),
                new SearchResultEntry($entry)
            );
        }
        $messages[] = new LdapMessageResponse(
            $message->getMessageId(),
            new SearchResultDone(ResultCode::SUCCESS)
        );

        $queue->sendMessage(...$messages);
    }
}
