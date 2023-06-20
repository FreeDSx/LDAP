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

namespace spec\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use PhpSpec\ObjectBehavior;

class SyncReferralResultSpec extends ObjectBehavior
{

    public function let(): void
    {
        $this->beConstructedWith(new ReferralResult(
            new LdapMessageResponse(
                1,
                new SearchResultReference(new LdapUrl('ldap://foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_DELETE,
                    'foo',
                    'bar'
                )
            )
        ));
    }

    public function it_should_get_the_referrals(): void
    {
        $this->getReferrals()
            ->shouldBeLike([new LdapUrl('ldap://foo')]);
    }

    public function it_should_get_the_raw_nessage(): void
    {
        $this->getMessage()
            ->shouldBeLike(
                new LdapMessageResponse(
                    1,
                    new SearchResultReference(new LdapUrl('ldap://foo')),
                    new SyncStateControl(
                        SyncStateControl::STATE_DELETE,
                        'foo',
                        'bar'
                    )
                )
            );
    }
}
