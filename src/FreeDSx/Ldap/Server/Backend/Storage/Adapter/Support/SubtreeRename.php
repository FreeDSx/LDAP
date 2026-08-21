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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;

/**
 * The DN rewrite a subtree rename applies, shared so every adapter moves a subtree the same way.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubtreeRename
{
    /**
     * Canonical form of the DN being moved.
     */
    public string $lcFrom;

    /**
     * Canonical form of the DN it moves to.
     */
    public string $lcTo;

    /**
     * Stored form of the DN it moves to.
     */
    public string $toDisplay;

    /**
     * @param Dn $from The DN being moved.
     * @param Dn $to The DN it moves to.
     * @param string $fromDisplay The stored form of $from, which descendants carry as their ancestor portion.
     *
     * @throws InvalidArgumentException when either DN is empty or the target sits at or under the source
     */
    public function __construct(
        public Dn $from,
        public Dn $to,
        public string $fromDisplay,
    ) {
        $this->lcFrom = $from->normalize()->toString();
        $this->lcTo = $to->normalize()->toString();
        $this->toDisplay = $to->toString();

        if ($this->lcFrom === '' || $this->lcTo === '') {
            throw new InvalidArgumentException('A subtree rename requires a source and a target DN.');
        }

        if ($to->isDescendantOf($from)) {
            throw new InvalidArgumentException(
                sprintf(
                    'Cannot move "%s" to "%s", which sits within its own subtree.',
                    $from->toString(),
                    $to->toString(),
                ),
            );
        }
    }

    /**
     * Whether the entry at the given DN moves with this rename.
     */
    public function covers(Dn $dn): bool
    {
        return $dn->isDescendantOf($this->from);
    }

    /**
     * Re-keys every covered row of $rows, which are keyed by canonical DN.
     *
     * @template TRow
     *
     * @param array<string, TRow> $rows
     * @param callable(TRow): TRow $rename Rewrites the row itself, which carries its own stored DN.
     *
     * @return array<string, TRow>
     */
    public function applyTo(
        array $rows,
        callable $rename,
    ): array {
        $renamed = [];

        foreach ($rows as $lcDn => $row) {
            $lcDn = (string) $lcDn;

            if (!$this->covers(Dn::fromCanonical($lcDn))) {
                $renamed[$lcDn] = $row;

                continue;
            }

            $renamed[$this->canonicalFor($lcDn)] = $rename($row);
        }

        return $renamed;
    }

    /**
     * The canonical DN an entry currently stored under $lcDn moves to.
     */
    public function canonicalFor(string $lcDn): string
    {
        return $this->replaceSuffix(
            $lcDn,
            $this->lcFrom,
            $this->lcTo,
        );
    }

    /**
     * The stored DN an entry moves to, keeping its own leading RDNs and taking the ancestor portion from the target.
     *
     * Spelling is only carried over where the stored DN ends in the source's stored form verbatim; anything else has
     * no prefix that can be split off reliably, so it takes the canonical DN.
     */
    public function storedFor(Dn $storedDn): Dn
    {
        $lcDn = $storedDn->normalize()->toString();
        if ($lcDn === $this->lcFrom) {
            return $this->to;
        }

        $stored = $storedDn->toString();
        if (!str_ends_with($stored, $this->fromDisplay) || $stored === $this->fromDisplay) {
            return Dn::fromCanonical($this->canonicalFor($lcDn));
        }

        return new Dn($this->replaceSuffix(
            $stored,
            $this->fromDisplay,
            $this->toDisplay,
        ));
    }

    private function replaceSuffix(
        string $subject,
        string $suffix,
        string $replacement,
    ): string {
        return substr(
            $subject,
            0,
            -strlen($suffix),
        ) . $replacement;
    }
}
