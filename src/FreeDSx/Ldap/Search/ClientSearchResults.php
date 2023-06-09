<?php

declare(strict_types=1);

namespace FreeDSx\Ldap\Search;

use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;

final class ClientSearchResults
{
    /**
     * @var EntryResult[]
     */
    private array $entryResults;

    /**
     * @var ReferralResult[]
     */
    private array $referralResults;

    private LdapMessageResponse $searchResultDone;

    /**
     * @param EntryResult[] $entryResults
     * @param ReferralResult[] $referralResults
     */
    public function __construct(
        array $entryResults,
        array $referralResults,
        LdapMessageResponse $searchResultDone,
    ) {
        $this->entryResults = $entryResults;
        $this->referralResults = $referralResults;
        $this->searchResultDone = $searchResultDone;
    }

    /**
     * @return ReferralResult[]
     */
    public function getReferrals(): array
    {
        return $this->referralResults;
    }

    /**
     * @return EntryResult[]
     */
    public function getEntryResults(): array
    {
        return $this->entryResults;
    }

    public function getDoneResult(): SearchResultDone
    {
        $searchDone = $this->searchResultDone->getResponse();

        if (!$searchDone instanceof SearchResultDone) {
            throw new UnexpectedValueException(sprintf(
                'Expected an instance of "%s" but got "%s".',
                SearchResultDone::class,
                get_class($searchDone),
            ));
        }

        return $searchDone;
    }
}
