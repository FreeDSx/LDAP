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
    private int $iteration = 1;

    private ?DateTimeInterface $lastProcessed = null;

    private string $uniqueId;

    private bool $hasProcessed = false;

    public function __construct(
        private PagingControl $control,
        private readonly SearchRequest $request,
        private readonly ControlBag $controls,
        private string $nextCookie,
        private readonly DateTimeInterface $created = new DateTime(),
        ?string $uniqueId = null
    ) {
        $this->uniqueId = $uniqueId ?? random_bytes(16);
    }

    /**
     * An opaque value that uniquely identifies this paging request across its lifecycle.
     */
    public function getUniqueId(): string
    {
        return $this->uniqueId;
    }

    /**
     * Whether the paging control is considered critical or not.
     */
    public function isCritical(): bool
    {
        return $this->control->getCriticality();
    }

    /**
     * When the paging request was originally created.
     */
    public function createdAt(): DateTimeInterface
    {
        return $this->created;
    }

    /**
     * When the request was last processed. May be null if not processed yet.
     */
    public function lastProcessedAt(): ?DateTimeInterface
    {
        return $this->lastProcessed;
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
     * The current iteration of paging that this request represents. Incremented by one for each request.
     */
    public function getIteration(): int
    {
        return $this->iteration;
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
     * Whether this represents the start of an unprocessed paging request.
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
     * @internal
     */
    public function getNextCookie(): string
    {
        return $this->nextCookie;
    }

    /**
     * @internal
     */
    public function updatePagingControl(PagingControl $pagingControl): void
    {
        $this->control = $pagingControl;
    }

    /**
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
