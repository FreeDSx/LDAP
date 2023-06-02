<?php

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
use FreeDSx\Ldap\Operation\LdapResult;

/**
 * This response encapsulates the entries returned from the search overall, along with the LDAP result at the end.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SearchResponse extends LdapResult
{
    private Entries $entries;

    public function __construct(
        LdapResult $result,
        Entries $entries
    ) {
        $this->entries = $entries;
        parent::__construct(
            $result->resultCode,
            $result->dn,
            $result->diagnosticMessage,
            ...$result->referrals
        );
    }

    public function getEntries(): Entries
    {
        return $this->entries;
    }
}
