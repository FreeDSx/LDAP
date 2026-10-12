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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Middleware\TargetDnSyntaxMiddleware;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;

final class TargetDnSyntaxMiddlewareTest extends TestCase
{
    private TargetDnSyntaxMiddleware $subject;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->subject = new TargetDnSyntaxMiddleware();
        $this->next = new RecordingMiddlewareHandler(new CallLog());
    }

    #[DataProvider('malformedDnProvider')]
    public function test_a_request_naming_a_malformed_dn_is_refused_with_invalid_dn_syntax(RequestInterface $request): void
    {
        try {
            $this->subject->process(
                $this->contextFor($request),
                $this->next,
            );
            self::fail('A request naming a malformed DN should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }

        self::assertNull($this->next->received);
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function malformedDnProvider(): iterable
    {
        yield 'a modify target' => [
            Operations::modify(
                'nonsense,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    'x',
                ),
            ),
        ];
        yield 'a delete target' => [Operations::delete('cn=a,,dc=foo,dc=bar')];
        yield 'a compare target' => [
            Operations::compare(
                '=x,dc=foo,dc=bar',
                'cn',
                'x',
            ),
        ];
        yield 'a rename target' => [
            new ModifyDnRequest(
                '=x,dc=foo,dc=bar',
                'cn=b',
                true,
            ),
        ];
        yield 'a new superior' => [
            Operations::move(
                'cn=a,dc=foo,dc=bar',
                'nonsense,dc=foo,dc=bar',
            ),
        ];
        yield 'a search base' => [Operations::search(Filters::present('objectClass'))->base('nonsense')];
    }

    #[DataProvider('wellFormedDnProvider')]
    public function test_a_request_naming_only_well_formed_dns_passes_through(RequestInterface $request): void
    {
        $this->subject->process(
            $this->contextFor($request),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function wellFormedDnProvider(): iterable
    {
        yield 'a modify target' => [
            Operations::modify(
                'cn=a,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    'x',
                ),
            ),
        ];
        yield 'a rename under the root' => [
            Operations::move(
                'cn=a,dc=foo,dc=bar',
                '',
            ),
        ];
        yield 'a search of the root DSE' => [Operations::search(Filters::present('objectClass'))->base('')];
        yield 'a request naming no DN' => [Operations::whoami()];
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            1,
            $request,
        ));
    }
}
