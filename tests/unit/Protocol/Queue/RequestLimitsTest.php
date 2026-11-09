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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Queue;

use FreeDSx\Asn1\Encoder\EncoderOptions;
use FreeDSx\Ldap\Protocol\Queue\RequestLimits;
use PHPUnit\Framework\TestCase;

final class RequestLimitsTest extends TestCase
{
    private RequestLimits $subject;

    protected function setUp(): void
    {
        $this->subject = new RequestLimits(
            maxSize: 1_024,
            maxElements: 50,
        );
    }

    public function testItHoldsARequestToItsSizeAndElementLimits(): void
    {
        self::assertEquals(
            new EncoderOptions(
                maxLength: 1_024,
                maxElements: 50,
            ),
            $this->subject->encoderOptions(),
        );
    }

    public function testItSetsNoLimitsByDefault(): void
    {
        self::assertEquals(
            new EncoderOptions(),
            (new RequestLimits())->encoderOptions(),
        );
    }
}
