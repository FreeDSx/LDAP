<?php
/**
 * This file is part of the FreeDSx package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;

/**
 * This response encapsulates the entries returned from the search overall, along with the LDAP result at the end.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchResponse extends LdapResult
{
    /**
     * @var Entry[]
     */
    protected $entries;

    /**
     * @param LdapResult $result
     * @param Entry[] ...$entries
     */
    public function __construct(LdapResult $result, Entry ...$entries)
    {
        $this->entries = $entries;
        parent::__construct($result->resultCode, $result->dn, $result->diagnosticMessage, ...$result->referrals);
    }

    /**
     * @return Entry[]
     */
    public function getEntries() : array
    {
        return $this->entries;
    }
}
