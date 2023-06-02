<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Vlv\VlvControl;
use FreeDSx\Ldap\Control\Vlv\VlvResponseControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Search\Filter\GreaterThanOrEqualFilter;

/**
 * Provides a simple wrapper around a VLV (Virtual List View) search operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Vlv
{
    private LdapClient $client;

    private SearchRequest $search;

    private ?VlvResponseControl $control = null;

    private int $before;

    private int $after;

    private int $offset = 1;

    private ?GreaterThanOrEqualFilter $filter = null;

    private SortingControl $sort;

    private bool $asPercentage = false;

    public function __construct(
        LdapClient $client,
        SearchRequest $search,
        SortingControl|SortKey|string $sort,
        int $after = 100,
        int $before = 0
    ) {
        $this->client = $client;
        $this->search = $search;
        $this->sort = $sort instanceof SortingControl ? $sort : Controls::sort($sort);
        $this->before = $before;
        $this->after = $after;
    }

    /**
     * As a percentage the moveTo, moveForward, moveBackward, and position methods work with numbers 0 - 100 and should
     * be interpreted as percentages.
     */
    public function asPercentage(bool $asPercentage = true): self
    {
        $this->asPercentage = $asPercentage;

        return $this;
    }

    /**
     * Request to start at a specific offset/percentage of entries.
     */
    public function startAt(int $offset): self
    {
        $this->offset = $offset;

        return $this;
    }

    /**
     * Move backward the specified number or percentage from the current position.
     */
    public function moveBackward(int $size): self
    {
        $this->offset = ($this->offset - $size < 0) ? 0 : $this->offset - $size;

        return $this;
    }

    /**
     * Move forward the specified number or percentage from the current position.
     */
    public function moveForward(int $size): self
    {
        $this->offset = ($this->asPercentage && ($this->offset + $size) > 100) ? 100 : $this->offset + $size;

        return $this;
    }

    /**
     * Moves the starting entry of the list to a specific position/percentage of the total list. An alias for startAt().
     */
    public function moveTo(int $position): self
    {
        return $this->startAt($position);
    }

    /**
     * Retrieve the following number of entries after the position specified.
     */
    public function afterPosition(int $after): self
    {
        $this->after = $after;

        return $this;
    }

    /**
     * Retrieve the following number of entries before the position specified.
     */
    public function beforePosition(int $before): self
    {
        $this->before = $before;

        return $this;
    }

    /**
     * Get the server's entry offset of the current list.
     */
    public function listOffset(): ?int
    {
        return ($this->control !== null) ? $this->control->getOffset() : null;
    }

    /**
     * Get the severs estimate, from the last request, that indicates how many entries are in the list.
     */
    public function listSize(): ?int
    {
        return ($this->control !== null) ? $this->control->getCount() : null;
    }

    /**
     * Get the current position in the list. When as percentage was specified this will be expressed as a percentage.
     * Use listOffset for a specific entry offset position.
     */
    public function position(): ?int
    {
        $control = $this->control;
        $pos = $control?->getOffset();
        if ($control === null || $pos === null) {
            return null;
        }

        if ($this->asPercentage) {
            return (int) round($pos / ((int) $control->getCount() / 100));
        } else {
            return $control->getOffset();
        }
    }

    /**
     * Whether we are at the end of the list.
     */
    public function isAtEndOfList(): bool
    {
        if ($this->control === null) {
            return false;
        }

        $control = $this->control;
        if ((((int) $control->getOffset() + $this->after) >= (int) $control->getCount())) {
            return true;
        }

        return $control->getOffset() === $control->getCount();
    }

    /**
     * Whether we are currently at the start of the list.
     */
    public function isAtStartOfList(): bool
    {
        if ($this->control === null) {
            return false;
        }
        $control = $this->control;
        if ($this->before !== 0 && ((int) $control->getOffset() - $this->before) <= 1) {
            return true;
        }

        return $control->getOffset() === 1;
    }

    /**
     * @throws ProtocolException
     * @throws OperationException
     */
    public function getEntries(): Entries
    {
        return $this->send();
    }

    /**
     * @throws OperationException
     * @throws ProtocolException
     */
    private function send(): Entries
    {
        $contextId = ($this->control !== null) ? $this->control->getContextId() : null;
        $message = $this->client->sendAndReceive($this->search, $this->createVlvControl($contextId), $this->sort);
        $control = $message->controls()->get(Control::OID_VLV_RESPONSE);
        if (!$control instanceof VlvResponseControl) {
            throw new ProtocolException('Expected a VLV response control, but received none.');
        }
        $this->control = $control;
        /** @var SearchResponse $response */
        $response = $message->getResponse();

        return $response->getEntries();
    }

    private function createVlvControl(?string $contextId): VlvControl
    {
        if ($this->filter !== null) {
            return Controls::vlvFilter(
                before: $this->before,
                after: $this->after,
                filter: $this->filter,
                contextId: $contextId,
            );
        }
        # An offset of 1 and a content size of zero starts from the beginning entry (server uses its assumed count).
        $count = ($this->control !== null)
            ? (int) $this->control->getCount()
            : 0;

        # In percentage mode start off with an assumed count of 100, as the formula the server uses should give us the
        # expected result
        if ($this->control === null && $this->asPercentage) {
            $count = 100;
        }

        $offset = $this->offset;
        # Final checks to make sure if we are using a percentage that valid values are used.
        if ($this->asPercentage && $this->offset > 100) {
            $offset = 100;
        } elseif ($this->asPercentage && $this->offset < 0) {
            $offset = 0;
        }

        if ($this->asPercentage && $this->control !== null) {
            $offset = (int) round(((int) $this->control->getCount() / 100) * $offset);
        }

        return Controls::vlv(
            before: $this->before,
            after: $this->after,
            offset: $offset,
            count: $count,
            contextId: $contextId,
        );
    }
}
