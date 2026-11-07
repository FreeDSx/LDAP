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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use PHPUnit\Framework\TestCase;

class LdapMessageResponseTest extends TestCase
{
    private LdapMessageResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new LdapMessageResponse(
            1,
            new SearchResponse(
                new SearchResultDone(
                    0,
                    'dc=foo,dc=bar',
                    '',
                ),
            ),
            new Control('foo'),
        );
    }

    public function test_it_should_get_the_response(): void
    {
        self::assertInstanceof(
            SearchResponse::class,
            $this->subject->getResponse(),
        );
    }

    public function test_it_should_get_the_controls(): void
    {
        self::assertTrue($this->subject->controls()->has('foo'));
    }

    public function test_it_should_get_the_message_id(): void
    {
        self::assertSame(
            1,
            $this->subject->getMessageId(),
        );
    }
}
