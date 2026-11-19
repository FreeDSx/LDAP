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

use Closure;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeRecord;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;

use function array_key_exists;

/**
 * What a window of journal changes says about each entry, such as its latest change and the last DN the consumer saw.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ChangeWindow
{
    /**
     * @var array<string, int>
     */
    private array $latestSeqs = [];

    /**
     * @var array<string, string> the last in-scope DN the sync identity could see each entry at
     */
    private array $lastVisible = [];

    /**
     * @var array<string, true>
     */
    private array $changedEarlier = [];

    /**
     * @var array<string, true>
     */
    private array $added = [];

    /**
     * @var array<string, string> each added or renamed entry's entryUUID, by its latest normalized DN
     */
    private array $holders = [];

    /**
     * @var array<string, string> the normalized DN each holder is known by, by entryUUID
     */
    private array $heldDns = [];

    /**
     * @var array<string, true>
     */
    private array $sent = [];

    /**
     * @var array<string, string> the canonical form of each DN looked up, by the form it was written in
     */
    private array $canonicalDns = [];

    /**
     * @param Closure(Dn): bool $isVisible
     */
    public function __construct(
        private readonly ChangeScope $scope,
        private readonly Closure $isVisible,
    ) {}

    /**
     * Read in journal order, which makes an entry's first rename the one that tells where the consumer held it.
     */
    public function record(ChangeRecord $record): void
    {
        $change = $record->change;
        $uuid = $change->entryUuid;
        $isFirst = !array_key_exists(
            $uuid,
            $this->latestSeqs,
        );
        $this->latestSeqs[$uuid] = $record->seq;

        if (!$isFirst) {
            $this->changedEarlier[$uuid] = true;
        }

        $this->recordAdded($change);
        $this->recordHolder($change);

        if ($isFirst && $change->changeType === ChangeType::ModRdn && $change->previousDn !== null) {
            $this->see(
                $uuid,
                $change->previousDn,
            );
        }

        $this->see(
            $uuid,
            $change->dn,
        );
    }

    public function isLatest(ChangeRecord $record): bool
    {
        return ($this->latestSeqs[$record->change->entryUuid] ?? null) === $record->seq;
    }

    /**
     * Whether the window changed the entry before its latest change.
     */
    public function hasEarlierChange(string $entryUuid): bool
    {
        return isset($this->changedEarlier[$entryUuid]);
    }

    /**
     * Whether the entry's latest change in the window added it.
     */
    public function isAdded(string $entryUuid): bool
    {
        return isset($this->added[$entryUuid]);
    }

    /**
     * The last in-scope DN the sync identity could see the entry at, or null when it never could in this window.
     */
    public function lastVisible(string $entryUuid): ?Dn
    {
        $dn = $this->lastVisible[$entryUuid] ?? null;

        return $dn === null
            ? null
            : new Dn($dn);
    }

    /**
     * The entry added or renamed in the window that now holds the DN's parent, unless it was sent already.
     */
    public function unsentHolderOfParent(Dn $dn): ?string
    {
        if ($this->holders === []) {
            return null;
        }

        $parent = $dn->getParent();

        return $parent === null
            ? null
            : $this->unsentHolderAt($parent->toString());
    }

    public function markSent(string $entryUuid): void
    {
        $this->sent[$entryUuid] = true;
    }

    public function wasSent(string $entryUuid): bool
    {
        return isset($this->sent[$entryUuid]);
    }

    private function unsentHolderAt(string $dn): ?string
    {
        // Siblings share a parent, so its canonical form is worked out once.
        $uuid = $this->holders[$this->canonicalDns[$dn] ??= Dn::normalized($dn)] ?? null;

        return $uuid === null || $this->wasSent($uuid)
            ? null
            : $uuid;
    }

    private function recordAdded(PendingChange $change): void
    {
        if ($change->changeType === ChangeType::Add) {
            $this->added[$change->entryUuid] = true;

            return;
        }

        unset($this->added[$change->entryUuid]);
    }

    /**
     * Keys an added or renamed entry by its new DN, and forgets the DN it held before or once it is deleted.
     */
    private function recordHolder(PendingChange $change): void
    {
        if ($change->changeType === ChangeType::Modify) {
            return;
        }

        $uuid = $change->entryUuid;
        $previous = $this->heldDns[$uuid] ?? null;

        if ($previous !== null && ($this->holders[$previous] ?? null) === $uuid) {
            unset($this->holders[$previous]);
        }
        unset($this->heldDns[$uuid]);

        if ($change->changeType === ChangeType::Delete) {
            return;
        }

        $name = $change->dn->normalizedString();
        $this->holders[$name] = $uuid;
        $this->heldDns[$uuid] = $name;
    }

    private function see(
        string $uuid,
        Dn $dn,
    ): void {
        $name = $dn->toString();

        if (($this->lastVisible[$uuid] ?? null) === $name) {
            return;
        }

        if ($this->scope->contains($dn) && ($this->isVisible)($dn)) {
            $this->lastVisible[$uuid] = $name;
        }
    }
}
