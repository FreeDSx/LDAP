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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\RequestHandlerInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Determines whether we can page results if no paging handler is defined.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerPagingUnsupportedHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly RequestHandlerInterface $dispatcher,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token
    ): void {
        $context = new RequestContext(
            $message->controls(),
            $token
        );
        $request = $this->getSearchRequestFromMessage($message);
        $pagingControl = $this->getPagingControlFromMessage($message);

        /**
         * RFC 2696, Section 3:
         *
         * If the server does not support this control, the server
         * MUST return an error of unsupportedCriticalExtension if the client
         * requested it as critical, otherwise the server SHOULD ignore the
         * control.
         */
        if ($pagingControl->getCriticality()) {
            throw new OperationException(
                'The server does not support the paging control.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION
            );
        }

        try {
            $searchResult = SearchResult::makeSuccessResult(
                $this->dispatcher->search(
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
            $this->queue
        );
    }
}
