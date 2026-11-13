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

namespace FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;

/**
 * One page's request of a paged search, as the client sent it.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class PagingRequest
{
    /**
     * @param ControlBag $controls The controls the backend acts on.
     */
    public function __construct(
        private PagingControl $control,
        private SearchRequest $request,
        private ControlBag $controls,
    ) {}

    /**
     * Whether the paging control is considered critical or not.
     */
    public function isCritical(): bool
    {
        return $this->control->getCriticality();
    }

    public function getSearchRequest(): SearchRequest
    {
        return $this->request;
    }

    public function controls(): ControlBag
    {
        return $this->controls;
    }

    public function getCookie(): string
    {
        return $this->control->getCookie();
    }

    /**
     * The size of the result set to return, as requested by the client.
     */
    public function getSize(): int
    {
        return $this->control->getSize();
    }

    /**
     * Whether this represents a request to abandon the paging request.
     */
    public function isAbandonRequest(): bool
    {
        return $this->control->getSize() === 0
            && $this->control->getCookie() !== '';
    }

    /**
     * Whether this starts a paged search rather than resuming one.
     */
    public function isPagingStart(): bool
    {
        return $this->control->getCookie() === '';
    }
}
