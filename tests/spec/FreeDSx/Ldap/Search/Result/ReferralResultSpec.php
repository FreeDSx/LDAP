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

namespace spec\FreeDSx\Ldap\Search\Result;

use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PhpSpec\ObjectBehavior;

class ReferralResultSpec extends ObjectBehavior
{
    public function let(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SearchResultReference(
                    new LdapUrl('foo'),
                ),
            )
        );
    }

    public function it_should_get_the_referrals(): void
    {
        $this->getReferrals()
            ->shouldBeLike([
                new LdapUrl('foo'),
            ]);
    }

    public function it_should_get_the_number_of_referrals(): void
    {
        $this->count()
            ->shouldBeEqualTo(1);
    }

    public function it_should_iterate_the_referrals(): void
    {
        $this->getIterator()
            ->shouldBeLike(
                new \ArrayIterator([
                    new LdapUrl('foo')
                ])
            );
    }

    public function it_should_have_a_string_representation_of_the_string_referral(): void
    {
        $this->__toString()
            ->shouldBeEqualTo('ldap://foo/');
    }
}
