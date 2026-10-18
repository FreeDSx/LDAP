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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation\SubtreeDelete;

use ArrayIterator;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use Iterator;

use function array_filter;
use function array_flip;
use function array_map;
use function array_values;
use function count;

/**
 * The entries a subtree delete has yet to remove.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class DeletionQueue
{
    /**
     * @var list<Iterator<int, string>>
     */
    private array $sources;

    public function __construct(
        private readonly SubtreeEnumerator $subtree,
        Dn $base,
    ) {
        $this->sources = [$subtree->leavesFirst($base)];
    }

    /**
     * The members that would be left holding a stray, being its parent or above it.
     *
     * @param list<string> $members canonical DNs
     * @param list<string> $strays canonical DNs
     *
     * @return list<string> in the order of the members
     */
    public static function blockedBy(
        array $members,
        array $strays,
    ): array {
        $blocking = [];
        foreach ($strays as $stray) {
            $blocking += array_flip(self::ancestorsOf($stray));
        }

        return array_values(array_filter(
            $members,
            static fn(string $member): bool => isset($blocking[$member]),
        ));
    }

    /**
     * @return list<string> canonical DNs
     */
    public function next(int $max): array
    {
        $dns = [];
        while (count($dns) < $max && $this->sources !== []) {
            $source = $this->sources[0];
            if (!$source->valid()) {
                array_shift($this->sources);

                continue;
            }
            $dns[] = $source->current();
            $source->next();
        }

        return $dns;
    }

    /**
     * Puts each stray's subtree ahead of the rest, followed by the members it kept from being removed.
     *
     * @param list<string> $strays canonical DNs
     * @param list<string> $blocked canonical DNs
     */
    public function requeue(
        array $strays,
        array $blocked,
    ): void {
        $ahead = array_map(
            fn(string $stray): Iterator => $this->subtree->leavesFirst(Dn::fromCanonical($stray)),
            $strays,
        );
        if ($blocked !== []) {
            $ahead[] = new ArrayIterator($blocked);
        }

        $this->sources = [
            ...$ahead,
            ...$this->sources,
        ];
    }

    /**
     * @return list<string> canonical DNs, nearest first
     */
    private static function ancestorsOf(string $dn): array
    {
        $ancestors = [];
        $parent = Dn::fromCanonical($dn)->getParent();

        while ($parent !== null) {
            $ancestors[] = $parent->normalizedString();
            $parent = $parent->getParent();
        }

        return $ancestors;
    }
}
