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

use FreeDSx\Ldap\Operation\Response\SyncInfo\SyncIdSet;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use Generator;

use function array_map;
use function count;

/**
 * Wraps sync results in their message envelope, coalescing runs of deletes into a syncIdSet per RFC 4533 §3.3.2.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SyncResultBatcher
{
    /**
     * UUIDs per set before it is flushed, holding a set to roughly 9KB so the RFC's "one or more" bounds the message.
     */
    public const MAX_SET_SIZE = 500;

    public function __construct(private int $maxSetSize = self::MAX_SET_SIZE) {}

    /**
     * @param iterable<SyncResult> $results
     * @return Generator<LdapMessageResponse>
     */
    public function batch(
        iterable $results,
        int $messageId,
    ): Generator {
        $deletes = [];

        foreach ($results as $result) {
            if (!$result->control->isDelete()) {
                yield $this->entry(
                    $messageId,
                    $result,
                );

                continue;
            }
            $deletes[] = $result;
            if (count($deletes) < $this->maxSetSize) {
                continue;
            }

            yield $this->idSet(
                $messageId,
                $deletes,
            );
            $deletes = [];
        }

        yield from $this->flush(
            $messageId,
            $deletes,
        );
    }

    /**
     * @param list<SyncResult> $deletes
     * @return Generator<LdapMessageResponse>
     */
    private function flush(
        int $messageId,
        array $deletes,
    ): Generator {
        // Only multiple deletes are coalesced
        if (count($deletes) === 1) {
            yield $this->entry(
                $messageId,
                $deletes[0],
            );

            return;
        }

        if ($deletes !== []) {
            yield $this->idSet(
                $messageId,
                $deletes,
            );
        }
    }

    /**
     * @param list<SyncResult> $deletes
     */
    private function idSet(
        int $messageId,
        array $deletes,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            $messageId,
            new SyncIdSet(
                array_map(
                    static fn(SyncResult $result): string => $result->control->getEntryUuid(),
                    $deletes,
                ),
                refreshDeletes: true,
            ),
        );
    }

    private function entry(
        int $messageId,
        SyncResult $result,
    ): LdapMessageResponse {
        return new LdapMessageResponse(
            $messageId,
            $result->entry,
            $result->control,
        );
    }
}
