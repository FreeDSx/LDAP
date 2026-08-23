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

namespace FreeDSx\Ldap\Sync\Provider;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\Server\Utility\Uuid;
use WeakMap;

/**
 * Turns a live entry or a journal change into an RFC 4533 sync result, gating on entry-level visibility and the filter.
 *
 * A visible entry is never ACL-redacted, since a replica must be a faithful copy; that is why the control itself is
 * privileged. The requested attribute selection is still honoured, as RFC 4533 §3.2 permits content that omits
 * attributes a normal search would return.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncResultProjector
{
    /**
     * Memo of the selection per request, which stays fixed for the life of a sync session.
     *
     * @var WeakMap<object, AttributeProjection>
     */
    private WeakMap $projections;

    public function __construct(
        private AccessControlInterface $accessControl,
        private FilterEvaluatorInterface $filterEvaluator,
        private Schema $schema,
        private EventLogger $eventLogger = new EventLogger(null),
    ) {
        $this->projections = new WeakMap();
    }

    /**
     * A search result (already filter-matched by the backend) as an add, if the consumer may see it.
     */
    public function projectSearched(
        Entry $entry,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        if (!$this->accessControl->isEntryVisible($token, $entry)) {
            return null;
        }

        return $this->addResult(
            $entry,
            $request,
        );
    }

    /**
     * A freshly fetched changed entry, or a delete once a change scopes it out (RFC 4533 §3.3.1).
     */
    public function projectFetched(
        Entry $entry,
        PendingChange $change,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        // An entry it can no longer see needs the pre-image to know whether announcing it would leak.
        if (!$this->accessControl->isEntryVisible($token, $entry)) {
            return $this->projectDeleted(
                $change,
                $request,
                $token,
            );
        }

        // Still visible, so announcing leaks nothing and no pre-image is needed.
        if (!$this->filterEvaluator->evaluate($entry, $request->getFilter())) {
            return $this->deleteResult(
                $change->dn,
                $change->entryUuid,
            );
        }

        return $this->addResult(
            $entry,
            $request,
            $change->changeType === ChangeType::Add
                ? SyncStateControl::STATE_ADD
                : SyncStateControl::STATE_MODIFY,
        );
    }

    /**
     * A delete, announced only if the consumer could have seen the entry (checked against its pre-image), so a
     * gone entry never leaks a DN/UUID the read-side ACL would have hidden.
     */
    public function projectDeleted(
        PendingChange $change,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        if (!$this->wasVisible($request, $token, $change->preImage)) {
            return null;
        }

        return $this->deleteResult(
            $change->dn,
            $change->entryUuid,
        );
    }

    /**
     * A move out of the consumer's content, announced as a delete at the DN it left (RFC 4533 §4.1).
     */
    public function projectMovedOut(
        Entry $entry,
        PendingChange $change,
        TokenInterface $token,
    ): ?SyncResult {
        // Still live, so visibility is judged from where it went rather than a pre-image a move never carries.
        if ($change->previousDn === null || !$this->accessControl->isEntryVisible($token, $entry)) {
            return null;
        }

        return $this->deleteResult(
            $change->previousDn,
            $change->entryUuid,
        );
    }

    private function deleteResult(
        Dn $dn,
        string $entryUuid,
    ): ?SyncResult {
        $binaryUuid = $this->binaryUuidOrSkip(
            $entryUuid,
            $dn,
        );

        if ($binaryUuid === null) {
            return null;
        }

        return new SyncResult(
            new SearchResultEntry(new Entry($dn)),
            new SyncStateControl(
                SyncStateControl::STATE_DELETE,
                $binaryUuid,
            ),
        );
    }

    private function addResult(
        Entry $entry,
        SearchRequest $request,
        int $state = SyncStateControl::STATE_ADD,
    ): ?SyncResult {
        // Read before projecting: the UUID keys the entry for the consumer, but a selection may exclude it.
        $uuid = $entry->get(AttributeTypeOid::NAME_ENTRY_UUID)?->firstValue();

        if ($uuid === null || $uuid === '') {
            return null;
        }

        $binaryUuid = $this->binaryUuidOrSkip(
            $uuid,
            $entry->getDn(),
        );

        if ($binaryUuid === null) {
            return null;
        }

        return new SyncResult(
            new SearchResultEntry($this->projectionFor($request)->project($entry)),
            new SyncStateControl(
                $state,
                $binaryUuid,
            ),
        );
    }

    private function projectionFor(SearchRequest $request): AttributeProjection
    {
        return $this->projections[$request] ??= AttributeProjection::forRequest(
            $request->getAttributes(),
            $request->getAttributesOnly(),
            $this->schema,
        );
    }

    private function wasVisible(
        SearchRequest $request,
        TokenInterface $token,
        ?Entry $preImage,
    ): bool {
        if ($preImage === null) {
            return false;
        }

        return $this->accessControl->isEntryVisible($token, $preImage)
            && $this->filterEvaluator->evaluate($preImage, $request->getFilter());
    }

    /**
     * The 16-byte UUID for a sync state control, or null (skipping the entry) when the stored entryUUID is
     * malformed, so one corrupt value cannot abort the whole stream.
     */
    private function binaryUuidOrSkip(
        string $uuid,
        Dn $dn,
    ): ?string {
        try {
            return Uuid::toBinary($uuid);
        } catch (InvalidArgumentException) {
            $this->eventLogger->record(
                ServerEvent::SyncEntrySkipped,
                [
                    EventContext::DN => $dn->toString(),
                    EventContext::REASON => 'invalid entryUUID',
                ],
            );

            return null;
        }
    }
}
