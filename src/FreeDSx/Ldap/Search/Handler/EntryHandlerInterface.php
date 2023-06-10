<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

declare(strict_types=1);

namespace FreeDSx\Ldap\Search\Handler;

use FreeDSx\Ldap\Search\Result\EntryResult;

interface EntryHandlerInterface
{
    public function handleEntry(EntryResult $entryResult): void;
}
