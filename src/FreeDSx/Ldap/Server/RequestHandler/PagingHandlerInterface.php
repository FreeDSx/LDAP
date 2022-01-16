<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use FreeDSx\Ldap\Server\RequestContext;

/**
 * Server implementations that wish to support paging must use a class implementing this interface.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface PagingHandlerInterface
{
    /**
     * Indicates a paging request that has been received and needs a response.
     *
     * @param PagingRequest $pagingRequest
     * @param RequestContext $context
     * @return PagingResponse
     */
    public function page(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): PagingResponse;

    /**
     * Indicates that a paging request is to be removed / abandoned. No further attempts will be made to complete it.
     * Any resources involved in its processing, if they still exist, should now be cleaned-up.
     *
     * This could be called in a couple of different contexts:
     *
     *  1. The client is explicitly asking to abandon the paging request.
     *  2. The client paging request is being removed due to server resource constraints (request age, max outstanding requests, etc)
     *  3. The paging request has been successfully completed and all results have been returned.
     *
     * @param PagingRequest $pagingRequest
     * @param RequestContext $context
     */
    public function remove(
        PagingRequest $pagingRequest,
        RequestContext $context
    ): void;
}
