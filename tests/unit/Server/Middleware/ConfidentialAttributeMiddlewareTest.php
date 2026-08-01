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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialAttributePolicy;
use FreeDSx\Ldap\Server\AccessControl\ConfidentialFilterRewriter;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Middleware\ConfidentialAttributeMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ConfidentialAttributeMiddlewareTest extends TestCase
{
    private MiddlewareHandlerInterface&MockObject $next;

    private TokenInterface $token;

    private ConfidentialAttributeMiddleware $subject;

    protected function setUp(): void
    {
        $this->next = $this->createMock(MiddlewareHandlerInterface::class);
        $this->token = BindToken::fromDn('cn=user,dc=foo,dc=bar');
        $this->subject = new ConfidentialAttributeMiddleware(new ConfidentialFilterRewriter(
            new ConfidentialAttributePolicy(
                new RuleBasedAccessControl(AclRules::fromEmpty()),
                SchemaResource::Core->load(),
            ),
        ));
    }

    public function test_a_search_on_a_withheld_attribute_succeeds_with_no_entries(): void
    {
        $this->next
            ->expects(self::never())
            ->method('handle');

        $stream = $this->subject->process(
            $this->context(
                Operations::search(Filters::equal('userPassword', 'secret'))
                    ->base('dc=foo,dc=bar'),
            ),
            $this->next,
        );

        self::assertSame(
            OperationOutcome::Succeeded,
            $stream->outcome()->outcome(),
        );
        self::assertSame(
            ResultCode::SUCCESS,
            $stream->outcome()->resultCode(),
        );
        self::assertCount(
            1,
            [...$stream->messages],
        );
    }

    public function test_a_search_keeping_a_branch_is_rewritten_and_passed_on(): void
    {
        $request = Operations::search(
            Filters::or(
                Filters::equal('cn', 'alice'),
                Filters::equal('userPassword', 'secret'),
            ),
        )->base('dc=foo,dc=bar');

        $this->next
            ->expects(self::once())
            ->method('handle')
            ->willReturn(ResponseStream::of([], OperationOutcomeResult::succeeded()));

        $this->subject->process(
            $this->context($request),
            $this->next,
        );

        self::assertSame(
            '(cn=alice)',
            $request->getFilter()->toString(),
        );
    }

    public function test_a_search_touching_nothing_confidential_is_left_alone(): void
    {
        $request = Operations::search(Filters::equal('cn', 'alice'))
            ->base('dc=foo,dc=bar');
        $filter = $request->getFilter();

        $this->next
            ->expects(self::once())
            ->method('handle')
            ->willReturn(ResponseStream::of([], OperationOutcomeResult::succeeded()));

        $this->subject->process(
            $this->context($request),
            $this->next,
        );

        self::assertSame(
            $filter,
            $request->getFilter(),
        );
    }

    public function test_a_compare_on_a_withheld_attribute_answers_compare_false(): void
    {
        $this->next
            ->expects(self::never())
            ->method('handle');

        $stream = $this->subject->process(
            $this->context(Operations::compare(
                'cn=alice,dc=foo,dc=bar',
                'userPassword',
                'secret',
            )),
            $this->next,
        );

        self::assertSame(
            OperationOutcome::Succeeded,
            $stream->outcome()->outcome(),
        );
        self::assertSame(
            ResultCode::COMPARE_FALSE,
            $stream->outcome()->resultCode(),
        );
    }

    public function test_a_compare_on_an_ordinary_attribute_is_passed_on(): void
    {
        $this->next
            ->expects(self::once())
            ->method('handle')
            ->willReturn(ResponseStream::of([], OperationOutcomeResult::succeeded()));

        $this->subject->process(
            $this->context(Operations::compare(
                'cn=alice,dc=foo,dc=bar',
                'cn',
                'alice',
            )),
            $this->next,
        );
    }

    public function test_an_unrelated_operation_is_passed_on(): void
    {
        $this->next
            ->expects(self::once())
            ->method('handle')
            ->willReturn(ResponseStream::of([], OperationOutcomeResult::succeeded()));

        $this->subject->process(
            $this->context(Operations::delete('cn=alice,dc=foo,dc=bar')),
            $this->next,
        );
    }

    private function context(RequestInterface $request): ServerRequestContext
    {
        return (new ServerRequestContext(new LdapMessageRequest(
            1,
            $request,
        )))->withToken($this->token);
    }
}
