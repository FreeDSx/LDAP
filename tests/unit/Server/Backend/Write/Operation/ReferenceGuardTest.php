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
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ReferenceIntegrityInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\UnresolvedReference;
use FreeDSx\Ldap\Server\Backend\Write\Operation\ReferenceGuard;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\MockObject\Stub;
use PHPUnit\Framework\TestCase;

final class ReferenceGuardTest extends TestCase
{
    private const GROUP_DN = 'cn=Team,dc=example,dc=com';

    private const REFUSAL = 'The attribute "uniquemember" of entry "cn=Team,dc=example,dc=com" names an entry that does not exist.';

    private ReferenceIntegrityInterface&Stub $references;

    private ReferenceGuard $subject;

    protected function setUp(): void
    {
        $this->references = $this->createStub(ReferenceIntegrityInterface::class);
        $this->subject = new ReferenceGuard($this->references);
    }

    public function test_a_write_naming_an_entry_that_is_not_stored_is_refused_naming_its_entry_and_attribute(): void
    {
        $this->references
            ->method('unresolvedReferences')
            ->willReturn(['uniquemember']);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->subject->assertResolved(
            new Dn(self::GROUP_DN),
            new WriteContext(
                new AnonToken(),
                new ControlBag(),
            ),
        );
    }

    public function test_a_batch_leaving_a_reference_unresolved_is_refused_naming_its_entry_and_attribute(): void
    {
        $this->references
            ->method('firstUnresolvedReference')
            ->willReturn(new UnresolvedReference(
                new Dn(self::GROUP_DN),
                'uniquemember',
            ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage(self::REFUSAL);

        $this->subject->assertNothingPending();
    }

    public function test_a_batch_leaving_nothing_unresolved_is_allowed(): void
    {
        $this->references
            ->method('firstUnresolvedReference')
            ->willReturn(null);

        $this->expectNotToPerformAssertions();

        $this->subject->assertNothingPending();
    }
}
