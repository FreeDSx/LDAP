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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Handles search request logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSearchHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    public function __construct(
        private readonly ServerQueue $queue,
        private readonly LdapBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
    ) {
    }

    /**
     * @inheritDoc
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token
    ): void {
        $request = $this->getSearchRequestFromMessage($message);

        try {
            $this->assertBaseDnProvided($request);

            $results = [];
            $sizeLimitExceeded = false;
            $sizeLimit = $request->getSizeLimit();

            $result = $this->backend->search(
                $request,
                $this->nonPagingControls($message),
            );

            foreach ($result->entries as $entry) {
                if ($result->isPreFiltered || $this->filterEvaluator->evaluate($entry, $request->getFilter())) {
                    $results[] = $this->applyAttributeFilter(
                        $entry,
                        $request->getAttributes(),
                        $request->getAttributesOnly(),
                    );
                    if ($sizeLimit > 0 && count($results) >= $sizeLimit) {
                        $sizeLimitExceeded = true;

                        break;
                    }
                }
            }

            $entries = new Entries(...$results);
            $searchResult = $sizeLimitExceeded
                ? SearchResult::makeErrorResult(
                    ResultCode::SIZE_LIMIT_EXCEEDED,
                    (string) $request->getBaseDn(),
                    '',
                    $entries,
                )
                : SearchResult::makeSuccessResult(
                    $entries,
                    (string) $request->getBaseDn()
                );
        } catch (OperationException $e) {
            $searchResult = SearchResult::makeErrorResult(
                $e->getCode(),
                (string) $request->getBaseDn(),
                $e->getMessage(),
            );
        }

        $this->sendEntriesToClient(
            $searchResult,
            $message,
            $this->queue,
        );
    }
}
