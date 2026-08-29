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

namespace FreeDSx\Ldap\Server\Backend\Storage\Import;

use FreeDSx\Ldap\Entry\Dn;

use function count;

/**
 * What a bulk import did, accumulated as it runs.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ImportResult
{
    private int $added = 0;

    /**
     * @var list<Dn>
     */
    private array $replaced = [];

    public function recordAdded(): void
    {
        $this->added++;
    }

    public function recordReplaced(Dn $dn): void
    {
        $this->replaced[] = $dn;
    }

    public function added(): int
    {
        return $this->added;
    }

    /**
     * @return list<Dn>
     */
    public function replaced(): array
    {
        return $this->replaced;
    }

    public function replacedCount(): int
    {
        return count($this->replaced);
    }
}
