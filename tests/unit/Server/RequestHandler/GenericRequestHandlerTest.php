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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\GenericRequestHandler;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class GenericRequestHandlerTest extends TestCase
{
    private GenericRequestHandler $subject;

    private RequestContext&MockObject $mockContext;

    protected function setUp(): void
    {
        $this->mockContext = $this->createMock(RequestContext::class);

        $this->subject = new GenericRequestHandler();
    }


    /**
     * @dataProvider unsupportedRequestDataProvider
     */
    public function test_it_should_throw_an_operations_exception_on_unsupported_requests(
        callable $method,
        RequestInterface $request
    ): void {
        self::expectException(OperationException::class);

        $method(
            $this->mockContext,
            $request,
        );
    }

    public function test_it_should_return_false_on_a_bind_request(): void
    {
        self::assertFalse(
            $this->subject->bind(
                'foo',
                'bar',
            ),
        );
    }

    /**
     * @return array<array{callable, RequestInterface}>
     */
    public static function unsupportedRequestDataProvider(): array
    {
        return [
            [(new GenericRequestHandler())->add(...), Operations::add(Entry::fromArray(''))],
            [(new GenericRequestHandler())->delete(...), Operations::delete('foo')],
            [(new GenericRequestHandler())->modify(...), Operations::modify('foo', Change::reset('foo'))],
            [(new GenericRequestHandler())->modifyDn(...), Operations::rename('foo', 'cn=bar')],
            [(new GenericRequestHandler())->search(...), Operations::search(Filters::equal('foo', 'bar'))],
            [(new GenericRequestHandler())->compare(...), Operations::compare('foo', 'bar', 'baz')],
            [(new GenericRequestHandler())->extended(...), Operations::extended('foo')],
        ];
    }
}
