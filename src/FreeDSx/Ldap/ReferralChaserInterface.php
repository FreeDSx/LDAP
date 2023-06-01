<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Ldap\Exception\SkipReferralException;
use FreeDSx\Ldap\Operation\Request\BindRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;

/**
 * An interface for referral chasing.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ReferralChaserInterface
{
    /**
     * Chase a referral for a request. Return a bind request to be used when chasing the referral. The $bind parameter
     * is the bind request the original LDAP client bound with (which may be null). Return null and no bind will be done.
     *
     * To skip a referral throw the SkipReferralException.
     *
     * @throws SkipReferralException
     */
    public function chase(
        LdapMessageRequest $request,
        LdapUrl $referral,
        ?BindRequest $bind
    ): ?BindRequest;

    /**
     * Construct the LdapClient with the options you want, and perform other tasks (such as StartTLS)
     *
     * @param array<string, mixed> $options
     */
    public function client(array $options): LdapClient;
}
