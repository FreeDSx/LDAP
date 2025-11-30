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

namespace Tests\Unit\FreeDSx\Ldap\Operation\Response;

use FreeDSx\Ldap\Operation\Response\AddResponse;
use PHPUnit\Framework\TestCase;

final class AddResponseTest extends TestCase
{
    private AddResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new AddResponse(
            0,
            'foo',
            'bar'
        );
    }

    public function test_it_has_the_expected_tag_number(): void
    {
        self::assertSame(
            9,
            $this->subject->toAsn1()->getTagNumber(),
        );
    }
}
