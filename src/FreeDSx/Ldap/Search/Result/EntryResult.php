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

namespace FreeDSx\Ldap\Search\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use Stringable;

final class EntryResult implements Stringable
{
    private ?Entry $entry = null;

    public function __construct(private readonly LdapMessageResponse $response)
    {}

    /**
     * The raw message response returned from the server, which contains any controls
     */
    public function getMessage(): LdapMessageResponse
    {
        return $this->response;
    }

    /**
     * Get the entry associated with this search result.
     */
    public function getEntry(): Entry
    {
        if ($this->entry !== null) {
            return $this->entry;
        }
        $entry = $this->response->getResponse();

        if (!$entry instanceof SearchResultEntry) {
            throw new UnexpectedValueException(sprintf(
                'Expected an instance of "%s", but got "%s".',
                SearchResultEntry::class,
                get_class($entry)
            ));
        }

        $this->entry = $entry->getEntry();

        return $this->entry;
    }

    /**
     * {@inheritDoc}
     */
    public function __toString(): string
    {
        return $this->getEntry()
            ->getDn()
            ->toString();
    }
}
