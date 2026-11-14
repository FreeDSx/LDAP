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
use FreeDSx\Ldap\Server\Initialization\RequirementInterface;
use PHPUnit\Framework\TestCase;

final class ProxyListenerContributorTest extends TestCase
{
    private RequirementInterface $requirement;

    private ProxyListenerContributor $subject;

    protected function setUp(): void
    {
        $this->requirement = $this->createStub(RequirementInterface::class);
        $this->subject = new ProxyListenerContributor([$this->requirement]);
    }

    public function test_it_contributes_the_requirements_it_was_given_and_no_advisories(): void
    {
        self::assertSame(
            [[$this->requirement], []],
            [$this->subject->requirements(), $this->subject->advisories()],
        );
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
