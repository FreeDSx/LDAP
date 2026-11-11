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

namespace Tests\Unit\FreeDSx\Ldap\Container\Contributor;

use FreeDSx\Ldap\Container\Contributor\ProxyListenerContributor;
use PHPUnit\Framework\TestCase;

final class ProxyListenerContributorTest extends TestCase
{
    private ProxyListenerContributor $subject;

    protected function setUp(): void
    {
        $this->subject = new ProxyListenerContributor();
    }

    public function test_each_client_holds_its_socket_and_its_upstream_connection(): void
    {
        self::assertSame(
            2,
            $this->subject->descriptorsPerClient(),
        );
    }

    public function test_it_supports_multiple_workers(): void
    {
        self::assertTrue($this->subject->supportsMultipleWorkers());
    }
}
