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

use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;

/**
 * A storage adapter that appends to a change journal injected on construction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ChangeJournalingInterface extends ChangeAppenderInterface
{
    /**
     * The change journal, for reading recorded changes (e.g. the RFC 4533 sync provider), or null when off.
     */
    public function changeJournal(): ?ChangeJournalInterface;
}
