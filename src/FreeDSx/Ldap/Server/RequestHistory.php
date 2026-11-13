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

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Server\Paging\PagingSessions;

/**
 * Used to retain history regarding certain client request details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class RequestHistory
{
    public function __construct(private PagingSessions $pagingSessions = new PagingSessions()) {}

    /**
     * The paged searches the client has left unfinished.
     */
    public function pagingSessions(): PagingSessions
    {
        return $this->pagingSessions;
    }
}
