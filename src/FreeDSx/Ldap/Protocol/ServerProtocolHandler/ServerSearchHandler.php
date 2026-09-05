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
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\Cancellation;
use FreeDSx\Ldap\Protocol\Queue\Response\QueueWriterConfig;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;

/**
 * Handles search request logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ServerSearchHandler implements ServerProtocolHandlerInterface
{
    use ServerSearchTrait;

    private const CANCEL_CHECK_INTERVAL = 50;

    public function __construct(
        private readonly ReadBackendInterface $backend,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly AccessControlInterface $accessControl,
        private readonly Schema $schema,
        private readonly SearchLimits $limits = new SearchLimits(),
    ) {}

    /**
     * @inheritDoc
     */
    public function handleRequest(
        LdapMessageRequest $message,
        TokenInterface $token,
    ): ResponseStream {
        $request = $this->getSearchRequestFromMessage($message);
        $state = new SearchResultState();
        $cancellation = new Cancellation();

        $this->assertBaseDnProvided($request);

        $sortControl = $this->sortingControl($message);
        $sortResponse = $this->sortingResponseControl(
            $sortControl,
            $this->schema,
        );

        $refusal = $this->refuseUnsortableCriticalSearch(
            $message,
            $sortControl,
            $sortResponse,
        );

        if ($refusal !== null) {
            return $refusal;
        }

        $backendResult = $this->backend->search(
            $request,
            $this->subentryVisibility($message->controls()),
            $this->controlsForBackend($message),
            $this->limits,
        );

        $projection = AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->schema,
        );
        $searchResult = SearchResult::makeSuccessResult(
            $this->filteredEntryStream(
                $backendResult,
                $request,
                $state,
                $token,
                $projection,
            ),
            $state,
        );

        $responseControls = $sortResponse !== null
            ? [$sortResponse]
            : [];

        return ResponseStream::streaming(
            $this->buildResponseStream(
                $searchResult,
                $message->getMessageId(),
                $cancellation,
                ...$responseControls,
            ),
            static fn(): SearchOperationResult => SearchOperationResult::success(
                $message,
                $state->entriesReturned,
            ),
            new QueueWriterConfig(signalInterval: self::CANCEL_CHECK_INTERVAL),
            $cancellation,
        );
    }

    /**
     * Streams filtered + attribute-projected entries from the backend.
     *
     * @return Generator<Entry>
     */
    private function filteredEntryStream(
        EntryStream $backend,
        SearchRequest $request,
        SearchResultState $state,
        TokenInterface $token,
        AttributeProjection $projection,
    ): Generator {
        $sizeLimit = $this->effectiveLimit(
            $request->getSizeLimit(),
            $this->limits->maxSearchSize(),
        );
        $filter = $request->getFilter();
        $emitted = 0;

        foreach ($backend->entries as $entry) {
            $filtered = $this->accessControl->filterEntry(
                $token,
                $entry,
            );

            if ($filtered === null) {
                continue;
            }

            if ($filtered !== $entry && !$this->filterEvaluator->evaluate($filtered, $filter)) {
                continue;
            }

            // A further match past the cap proves overflow: signal without emitting it.
            if ($sizeLimit > 0 && $emitted >= $sizeLimit) {
                $state->resultCode = ResultCode::SIZE_LIMIT_EXCEEDED;

                return;
            }

            yield $projection->project($filtered);
            $emitted++;
            $state->entriesReturned++;
        }
    }
}
