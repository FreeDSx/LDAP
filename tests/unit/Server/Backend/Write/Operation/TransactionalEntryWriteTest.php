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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Search\EntryProjection;
use FreeDSx\Ldap\Server\Backend\Write\Operation\TransactionalEntryWrite;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteControlEvaluator;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class TransactionalEntryWriteTest extends TestCase
{
    use ServerContainerTrait;

    private const GROUP = 'cn=Admins,dc=example,dc=com';

    private ReadEntryInterface&MockObject $reader;

    private AssertionEvaluator $assertions;

    private TransactionalEntryWrite $subject;

    protected function setUp(): void
    {
        $this->reader = $this->createMock(ReadEntryInterface::class);
        $this->assertions = $this->fromContainer(AssertionEvaluator::class);
        $this->subject = $this->fromContainer(
            TransactionalEntryWrite::class,
            [ReadEntryInterface::class => $this->reader],
        );
    }

    public function test_a_delete_a_control_reads_loads_every_link_of_its_target(): void
    {
        $this->expectTargetReadWithLinkCap(null);
        $controls = new ControlBag(new PreReadControl('member'));

        $this->subject->delete(
            new Dn(self::GROUP),
            new WriteContext(
                new AnonToken(),
                $controls,
                controlEvaluator: new WriteControlEvaluator(
                    $this->assertions,
                    new AnonToken(),
                    $controls,
                ),
            ),
            static function (): void {},
        );
    }

    public function test_a_delete_no_control_reads_leaves_the_links_of_its_target_unread(): void
    {
        $this->expectTargetReadWithLinkCap(0);

        $this->subject->delete(
            new Dn(self::GROUP),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
            ),
            static function (): void {},
        );
    }

    private function expectTargetReadWithLinkCap(?int $linkCap): void
    {
        $this->reader
            ->expects(self::once())
            ->method('find')
            ->with(
                self::anything(),
                self::callback(static fn(EntryProjection $projection): bool => $projection->linkCap === $linkCap),
            )
            ->willReturn(Entry::fromArray(
                self::GROUP,
                ['cn' => ['Admins']],
            ));
    }
}
