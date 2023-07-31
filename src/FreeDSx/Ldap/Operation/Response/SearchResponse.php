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

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Search\Result\EntryResult;
use FreeDSx\Ldap\Search\Result\ReferralResult;

/**
 * This response encapsulates the entries returned from the search overall, along with the LDAP result at the end.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchResponse extends SearchResultDone
{
    private ?Entries $entries = null;

    /**
     * @param EntryResult[] $entryResults
     * @param ReferralResult[] $referralResults
     */
    public function __construct(
        LdapResult $result,
        private readonly array $entryResults = [],
        private readonly array $referralResults = [],
    ) {
        parent::__construct(
            $result->getResultCode(),
            $result->getDn()->toString(),
            $result->getDiagnosticMessage(),
            ...$result->getReferrals()
        );
    }

    /**
     * Returns the {@see Entry} objects associated with this result set.
     */
    public function getEntries(): Entries
    {
        if ($this->entries !== null) {
            return $this->entries;
        }
        $entries = [];

        foreach ($this->entryResults as $entryResult) {
            $entries[] = $entryResult->getEntry();
        }

        $this->entries = new Entries(...$entries);

        return $this->entries;
    }

    /**
     * Return the {@see EntryResult} objects associated with this result set.
     *
     * The {@see EntryResult} contains the full LDAP message response, which includes the controls and result code.
     *
     * @return EntryResult[]
     */
    public function getEntryResults(): array
    {
        return $this->entryResults;
    }

    /**
     * Return the {@see ReferralResult} objects associated with this result set.
     *
     * The {@see ReferralResult} contains the full LDAP message response, which includes the controls and result code.
     *
     * @return ReferralResult[]
     */
    public function getReferralResults(): array
    {
        return $this->referralResults;
    }
}
