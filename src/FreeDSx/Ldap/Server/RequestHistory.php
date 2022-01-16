<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Server\Paging\PagingRequests;

/**
 * Used to retain history regarding certain client request details.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class RequestHistory
{
    /**
     * @var int[]
     */
    private $ids = [];

    /**
     * @var PagingRequests
     */
    private $pagingRequests;

    public function __construct(PagingRequests $pagingRequests = null)
    {
        $this->pagingRequests = $pagingRequests ?? new PagingRequests();
    }

    /**
     * Add a specific message ID that the client has used.
     *
     * @param int $id
     * @throws ProtocolException
     */
    public function addId(int $id): void
    {
        if ($id === 0 || in_array($id, $this->ids, true)) {
            throw new ProtocolException(sprintf(
                'The message ID %s is not valid.',
                $id
            ));
        }

        $this->ids[] = $id;
    }

    /**
     * The currently active paging requests from the client.
     *
     * @return PagingRequests
     */
    public function pagingRequest(): PagingRequests
    {
        return $this->pagingRequests;
    }
}
