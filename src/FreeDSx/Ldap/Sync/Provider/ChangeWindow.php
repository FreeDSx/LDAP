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
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Read\ChangeScope;

use function array_key_exists;

/**
 * What a window of journal changes says about each entry: its latest change, and the last DN the consumer could see.
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
     * The last in-scope DN the sync identity could see the entry at, or null when it never could in this window.
     */
    public function lastVisible(string $entryUuid): ?Dn
    {
        $dn = $this->lastVisible[$entryUuid] ?? null;

        return $dn === null
            ? null
            : new Dn($dn);
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
