<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Paging;

use DateTime;
use DateTimeInterface;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\Request\SearchRequest;

/**
 * Encapsulates the paging request from a client and provides some helpful methods.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PagingRequest
{
    /**
     * @var PagingControl
     */
    private $control;

    /**
     * @var SearchRequest
     */
    private $request;

    /**
     * @var ControlBag
     */
    private $controls;

    /**
     * @var int
     */
    private $iteration = 1;

    /**
     * @var string
     */
    private $nextCookie;

    /**
     * @var DateTimeInterface|null
     */
    private $lastProcessed = null;

    /**
     * @var DateTimeInterface
     */
    private $created;

    /**
     * @var string
     */
    private $uniqueId;

    /**
     * @var bool
     */
    private $hasProcessed = false;

    public function __construct(
        PagingControl $control,
        SearchRequest $request,
        ControlBag $controls,
        string $nextCookie,
        ?DateTimeInterface $created = null,
        ?string $uniqueId = null
    ) {
        $this->control = $control;
        $this->request = $request;
        $this->controls = $controls;
        $this->nextCookie = $nextCookie;
        $this->created = $created ?? new DateTime();
        $this->uniqueId = $uniqueId ?? random_bytes(16);
    }

    /**
     * An opaque value that uniquely identifies this paging request across its lifecycle.
     *
     * @return string
     */
    public function getUniqueId(): string
    {
        return $this->uniqueId;
    }

    /**
     * Whether the paging control is considered critical or not.
     *
     * @return bool
     */
    public function isCritical(): bool
    {
        return $this->control->getCriticality();
    }

    /**
     * When the paging request was originally created.
     *
     * @return DateTimeInterface
     */
    public function createdAt(): DateTimeInterface
    {
        return $this->created;
    }

    /**
     * When the request was last processed. May be null if not processed yet.
     *
     * @return DateTimeInterface|null
     */
    public function lastProcessedAt(): ?DateTimeInterface
    {
        return $this->lastProcessed;
    }

    /**
     * @return SearchRequest
     */
    public function getSearchRequest(): SearchRequest
    {
        return $this->request;
    }

    /**
     * @return ControlBag
     */
    public function controls(): ControlBag
    {
        return $this->controls;
    }

    /**
     * @return string
     */
    public function getCookie(): string
    {
        return $this->control->getCookie();
    }

    /**
     * The current iteration of paging that this request represents. Incremented by one for each request.
     *
     * @return int
     */
    public function getIteration(): int
    {
        return $this->iteration;
    }

    /**
     * The size of the result set to return, as requested by the client.
     *
     * @return int
     */
    public function getSize(): int
    {
        return $this->control->getSize();
    }

    /**
     * Whether this represents a request to abandon the paging request.
     *
     * @return bool
     */
    public function isAbandonRequest(): bool
    {
        return $this->control->getSize() === 0
            && $this->control->getCookie() !== '';
    }

    /**
     * Whether this represents the start of an unprocessed paging request.
     *
     * @return bool
     */
    public function isPagingStart(): bool
    {
        if ($this->hasProcessed) {
            return false;
        }

        return $this->control->getCookie() === ''
            && $this->control->getSize() >= 0;
    }

    /**
     * @return string
     * @internal
     */
    public function getNextCookie(): string
    {
        return $this->nextCookie;
    }

    /**
     * @param PagingControl $pagingControl
     * @internal
     */
    public function updatePagingControl(PagingControl $pagingControl): void
    {
        $this->control = $pagingControl;
    }

    /**
     * @param string $cookie
     * @internal
     */
    public function updateNextCookie(string $cookie): void
    {
        $this->nextCookie = $cookie;
    }

    /**
     * @internal
     */
    public function markProcessed(): void
    {
        $this->lastProcessed = new DateTime();
        $this->iteration++;
        $this->hasProcessed = true;
    }
}
