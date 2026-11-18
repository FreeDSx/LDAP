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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AttributeProjection;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
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
        private LinkedLeafWitness $linkedLeaves,
        private EventLogger $eventLogger = new EventLogger(null),
        private LinkedAttributes $linked = new LinkedAttributes(new Schema()),
    ) {
        $this->projections = new WeakMap();
    }

    /**
     * What a changed entry is read with: every linked value, and the back-links the request selects.
     */
    public function fetchProjectionFor(SearchRequest $request): EntryProjection
    {
        // @todo A replica needs every value in one message; offer ranged values to consumers that can complete them.
        return new EntryProjection(
            linkCap: null,
            backlinks: $this->linked
                ->backlinks()
                ->selectedBy($request->getAttributes()),
        );
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
     * Whether the sync identity could see an entry at the DN, which every access rule judges by the DN alone.
     */
    public function isVisibleAt(
        TokenInterface $token,
        Dn $dn,
    ): bool {
        return $this->accessControl->isEntryVisible(
            $token,
            new Entry($dn),
        );
    }

    /**
     * A freshly fetched changed entry, or a delete once a change scopes it out (RFC 4533 §3.3.1).
     *
     * @param ?Dn $lastVisible The last in-scope DN the sync identity could see the entry at in the window.
     */
    public function projectFetched(
        Entry $entry,
        string $entryUuid,
        bool $isAdded,
        ?Dn $lastVisible,
        SearchRequest $request,
        TokenInterface $token,
    ): ?SyncResult {
        if (!$this->accessControl->isEntryVisible($token, $entry)) {
            return $this->projectLeft(
                $entryUuid,
                $lastVisible,
            );
        }

        $filter = $request->getFilter();
        // A fetched entry carries only the selected back-links, and the witness adds the ones the filter names.
        $judged = $this->linkedLeaves->witness(
            $entry,
            $filter,
        );

        // Visible where it is now, so naming it there leaks nothing.
        if (!$this->filterEvaluator->evaluate($judged, $filter)) {
            return $this->deleteResult(
                $lastVisible ?? $entry->getDn(),
                $entryUuid,
            );
        }

        return $this->addResult(
            $entry,
            $request,
            $isAdded
                ? SyncStateControl::STATE_ADD
                : SyncStateControl::STATE_MODIFY,
        );
    }

    /**
     * A delete, named by the last DN the sync identity could see the entry at, if its pre-image matched the filter.
     *
     * @param ?Dn $lastVisible The last in-scope DN the sync identity could see the entry at in the window.
     */
    public function projectDeleted(
        PendingChange $change,
        ?Dn $lastVisible,
        SearchRequest $request,
    ): ?SyncResult {
        if ($lastVisible === null || $change->preImage === null) {
            return null;
        }

        $preImage = self::at(
            $change->preImage,
            $lastVisible,
        );

        if (!$this->matchedFilter($request, $preImage)) {
            return null;
        }

        return $this->deleteResult(
            $lastVisible,
            $change->entryUuid,
        );
    }

    /**
     * An entry gone from the consumer's view, named by the last DN the identity could see it at (RFC 4533 §7).
     *
     * @param ?Dn $lastVisible The last in-scope DN the sync identity could see the entry at in the window.
     */
    public function projectLeft(
        string $entryUuid,
        ?Dn $lastVisible,
    ): ?SyncResult {
        if ($lastVisible === null) {
            return null;
        }

        return $this->deleteResult(
            $lastVisible,
            $entryUuid,
        );
    }

    /**
     * The entry as it would stand at another DN, for a filter that names the DN.
     */
    private static function at(
        Entry $entry,
        Dn $dn,
    ): Entry {
        return new Entry(
            $dn,
            ...$entry->getAttributes(),
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
        $uuid = $entry->getUuid();

        if ($uuid === null) {
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

    private function matchedFilter(
        SearchRequest $request,
        Entry $preImage,
    ): bool {
        // A consumer ignores a delete for an entry it never held, where withholding one leaves it stale forever.
        if ($this->namesSomethingHeldApart($request->getFilter())) {
            return true;
        }

        return $this->filterEvaluator->evaluate($preImage, $request->getFilter());
    }

    /**
     * Whether the filter rests on values kept outside the entry.
     */
    private function namesSomethingHeldApart(FilterInterface $filter): bool
    {
        foreach (FilterAttributes::referenced($filter) ?? [] as $attribute) {
            if ($this->linked->heldApart(new Attribute($attribute))) {
                return true;
            }
        }

        return false;
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
