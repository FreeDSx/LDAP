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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerCompareHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\AccessControl\WithheldAttributePolicy;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\NoLinkedValues;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Operation\CompareOperationResult;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerCompareHandlerTest extends TestCase
{
    private ServerCompareHandler $subject;

    private ReadBackendInterface&MockObject $mockBackend;

    private TokenInterface&MockObject $mockToken;

    private AccessControlInterface&MockObject $mockAccessControl;

    private FilterEvaluatorInterface&MockObject $mockFilterEvaluator;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockBackend = $this->createMock(ReadBackendInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);
        $this->mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->mockAccessControl
            ->method('mayFilterOnAttribute')
            ->willReturnCallback(static fn(TokenInterface $token, string $attribute): bool => $attribute !== 'secret');

        $this->subject = new ServerCompareHandler(
            backend: $this->mockBackend,
            assertions: new AssertionEvaluator(
                $this->mockFilterEvaluator,
                $this->mockBackend,
                $this->mockAccessControl,
                new LinkedLeafWitness(
                    new NoLinkedValues(),
                    new LinkedAttributes(new Schema()),
                ),
            ),
            withheld: new WithheldAttributePolicy($this->mockAccessControl),
        );
    }

    public function test_it_compares_the_entry_it_reads_once(): void
    {
        $entry = Entry::fromArray(
            'cn=foo,dc=bar',
            ['foo' => ['bar']],
        );
        $compare = new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')));

        $this->mockBackend
            ->expects(self::never())
            ->method('get');
        $this->mockBackend
            ->expects(self::once())
            ->method('getOrFail')
            ->with(self::isInstanceOf(Dn::class))
            ->willReturn($entry);
        $this->mockBackend
            ->expects(self::once())
            ->method('compare')
            ->with(
                $entry,
                self::isInstanceOf(EqualityFilter::class),
            )
            ->willReturn(true);

        $outcome = $this->subject->handleRequest($compare, $this->mockToken)->outcome();

        self::assertInstanceOf(
            CompareOperationResult::class,
            $outcome,
        );
        self::assertSame(
            ResultCode::COMPARE_TRUE,
            $outcome->resultCode(),
        );
    }

    public function test_a_missing_compare_target_answers_before_its_assertion(): void
    {
        $compare = new LdapMessageRequest(
            1,
            new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')),
            Controls::assertion(Filters::equal('foo', 'nope')),
        );

        $this->mockBackend
            ->method('getOrFail')
            ->willThrowException(new OperationException(
                'No such object: cn=foo,dc=bar',
                ResultCode::NO_SUCH_OBJECT,
            ));
        $this->mockFilterEvaluator
            ->expects(self::never())
            ->method('evaluate');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::NO_SUCH_OBJECT);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_a_failing_assertion_refuses_the_compare_before_it_is_evaluated(): void
    {
        $compare = new LdapMessageRequest(
            1,
            new CompareRequest('cn=foo,dc=bar', Filters::equal('foo', 'bar')),
            Controls::assertion(Filters::equal('foo', 'nope')),
        );

        $this->mockBackend
            ->method('getOrFail')
            ->willReturn(Entry::fromArray(
                'cn=foo,dc=bar',
                ['foo' => ['bar']],
            ));
        $this->mockAccessControl
            ->method('stripUnreadableAttributes')
            ->willReturnArgument(1);
        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(false);
        $this->mockBackend
            ->expects(self::never())
            ->method('compare');

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_a_compare_on_a_withheld_attribute_answers_false_without_comparing(): void
    {
        $this->mockBackend
            ->method('getOrFail')
            ->willReturn(Entry::fromArray(
                'cn=foo,dc=bar',
                ['secret' => ['bar']],
            ));
        $this->mockBackend
            ->expects(self::never())
            ->method('compare');

        $outcome = $this->subject->handleRequest(
            new LdapMessageRequest(1, new CompareRequest('cn=foo,dc=bar', Filters::equal('secret', 'bar'))),
            $this->mockToken,
        )->outcome();

        self::assertInstanceOf(
            CompareOperationResult::class,
            $outcome,
        );
        self::assertSame(
            ResultCode::COMPARE_FALSE,
            $outcome->resultCode(),
        );
    }

    public function test_a_failing_assertion_refuses_a_compare_on_a_withheld_attribute(): void
    {
        $compare = new LdapMessageRequest(
            1,
            new CompareRequest('cn=foo,dc=bar', Filters::equal('secret', 'bar')),
            Controls::assertion(Filters::equal('foo', 'nope')),
        );

        $this->mockBackend
            ->method('getOrFail')
            ->willReturn(Entry::fromArray(
                'cn=foo,dc=bar',
                [
                    'foo' => ['bar'],
                    'secret' => ['bar'],
                ],
            ));
        $this->mockAccessControl
            ->method('stripUnreadableAttributes')
            ->willReturnArgument(1);
        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(false);

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->subject->handleRequest($compare, $this->mockToken);
    }

    public function test_it_refuses_a_request_that_is_not_a_compare(): void
    {
        $this->expectException(RuntimeException::class);

        $this->subject->handleRequest(
            new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=bar')),
            $this->mockToken,
        );
    }
}
