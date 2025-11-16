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

use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use PHPUnit\Framework\TestCase;

final class ModifyResponseTest extends TestCase
{
    private ModifyResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new ModifyResponse(0);
    }

    public function test_it_should_get_the_tag_number(): void
    {
        self::assertSame(
            7,
            $this->subject->toAsn1()->getTagNumber()
        );
    }
}
