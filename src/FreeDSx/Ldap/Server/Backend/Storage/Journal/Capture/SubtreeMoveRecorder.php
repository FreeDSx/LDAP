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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function strlen;
use function substr;

/**
 * Journals a relocation as one record per moved entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeMoveRecorder
{
    public function __construct(
        private ChangeRecorder $recorder,
        private SubtreeEnumerator $subtree,
    ) {}

    /**
     * A consumer re-fetches by the DN each record carries, so it would otherwise never hear about a descendant.
     */
    public function record(
        WriteContext $context,
        Entry $newEntry,
        Dn $previousDn,
        Dn $normOld,
        Dn $normNew,
    ): void {
        $this->recorder->recordModRdn(
            $newEntry,
            $previousDn,
            $context,
        );

        // Respelling the base leaves every DN beneath it exactly where it was.
        if ($normNew->toString() === $normOld->toString()) {
            return;
        }

        foreach ($this->subtree->descendantsOf($normNew) as $entry) {
            $this->recorder->recordModRdn(
                $entry,
                $this->previousDnOf(
                    $entry->getDn(),
                    $normOld,
                    $normNew,
                ),
                $context,
            );
        }
    }

    /**
     * Where a moved entry sat before, by swapping back the canonical suffix the move replaced.
     */
    private function previousDnOf(
        Dn $movedDn,
        Dn $normOld,
        Dn $normNew,
    ): Dn {
        $lcDn = $movedDn->normalize()->toString();

        return Dn::fromCanonical(
            substr(
                $lcDn,
                0,
                -strlen($normNew->toString()),
            ) . $normOld->toString(),
        );
    }
}
