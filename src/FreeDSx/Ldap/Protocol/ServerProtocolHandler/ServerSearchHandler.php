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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
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
    use ServerSearchTrait;

    /**
     * @inheritDoc
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
        RequestHandlerInterface $dispatcher,
        ServerQueue $queue
    ): void {
        $context = new RequestContext(
            $message->controls(),
            $token
        );
        $request = $this->getSearchRequestFromMessage($message);

        try {
            $searchResult = SearchResult::makeSuccessResult(
                $dispatcher->search(
                    $context,
                    $request
                ),
                (string) $request->getBaseDn()
            );
        } catch (OperationException $e) {
            $searchResult = SearchResult::makeErrorResult(
                $e->getCode(),
                (string) $request->getBaseDn(),
                $e->getMessage()
            );
        }

        $this->sendEntriesToClient(
            $searchResult,
            $message,
            $queue
        );
    }
}
