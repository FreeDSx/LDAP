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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;

final class RequestContextTest extends TestCase
{
    private RequestContext $subject;

    protected function setUp(): void
    {
        $this->subject = new RequestContext(
            new ControlBag(),
            new AnonToken(null)
        );
    }

    public function test_it_should_get_the_token(): void
    {
        self::assertEquals(
            new AnonToken(null),
            $this->subject->token(),
        );
    }

    public function test_it_should_get_the_controls(): void
    {
        self::assertEquals(
            new ControlBag(),
            $this->subject->controls(),
        );
    }
}
