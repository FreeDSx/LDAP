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

namespace Tests\Unit\FreeDSx\Ldap\Sync\Result;

use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\LdapUrl;
use FreeDSx\Ldap\Operation\Response\SearchResultReference;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Result\ReferralResult;
use FreeDSx\Ldap\Sync\Result\SyncReferralResult;
use PHPUnit\Framework\TestCase;

final class SyncReferralResultTest extends TestCase
{
    private SyncReferralResult $subject;

    protected function setUp(): void
    {
        $this->subject = new SyncReferralResult(
            new ReferralResult(
                new LdapMessageResponse(
                    1,
                    new SearchResultReference(new LdapUrl('ldap://foo')),
                    new SyncStateControl(
                        SyncStateControl::STATE_DELETE,
                        'foo',
                        'bar'
                    )
                )
            )
        );
    }

    public function test_it_should_get_the_referrals(): void
    {
        self::assertEquals(
            [new LdapUrl('ldap://foo')],
            $this->subject->getReferrals(),
        );
    }

    public function test_it_should_get_the_raw_message(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SearchResultReference(new LdapUrl('ldap://foo')),
                new SyncStateControl(
                    SyncStateControl::STATE_DELETE,
                    'foo',
                    'bar'
                )
            ),
            $this->subject->getMessage(),
        );
    }
}
