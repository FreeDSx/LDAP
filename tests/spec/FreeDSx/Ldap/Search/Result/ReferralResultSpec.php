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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\UnexpectedValueException;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
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

    public function it_must_have_a_SearchReferenceResponse(): void
    {
        $this->beConstructedWith(
            new LdapMessageResponse(
                1,
                new SearchResultEntry(
                    new Entry('cn=foo')
                ),
            )
        );

        $this->shouldThrow(new UnexpectedValueException(sprintf(
            'Expected an instance of "%s", but got "%s".',
            SearchResultReference::class,
            SearchResultEntry::class,
        )))->during('getReferrals');
    }
}
