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

use FreeDSx\Ldap\Operation\Response\CompareResponse;
use PHPUnit\Framework\TestCase;

final class CompareResponseTest extends TestCase
{
    private CompareResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new CompareResponse(0);
    }

    public function test_it_has_the_correct_tag_number(): void
    {
        self::assertSame(
            15,
            $this->subject->toAsn1()->getTagNumber()
        );
    }
}
