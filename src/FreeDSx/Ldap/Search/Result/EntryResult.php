<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Search\Result;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use Stringable;

final class EntryResult implements Stringable
{
    private LdapMessageResponse $response;

    private ?Entry $entry = null;

    public function __construct(LdapMessageResponse $response)
    {
        $this->response = $response;
    }

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
