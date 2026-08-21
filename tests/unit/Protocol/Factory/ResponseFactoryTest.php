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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Factory;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Response\AddResponse;
use FreeDSx\Ldap\Operation\Response\BindResponse;
use FreeDSx\Ldap\Operation\Response\CompareResponse;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\ModifyDnResponse;
use FreeDSx\Ldap\Operation\Response\ModifyResponse;
use FreeDSx\Ldap\Operation\Response\ResponseInterface;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Factory\ResponseFactory;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ResponseFactoryTest extends TestCase
{
    private ResponseFactory $subject;

    protected function setUp(): void
    {
        $this->subject = new ResponseFactory();
    }

    public function test_it_should_get_a_bind_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new BindResponse(new LdapResult(0, '', 'foo')),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new SimpleBindRequest('foo', 'bar'),
                ),
                0,
                'foo',
            ),
        );
    }

    public function test_it_should_get_an_add_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new AddResponse(0, ''),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new AddRequest(Entry::create('foo')),
                ),
            ),
        );
    }

    public function test_it_should_get_a_compare_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new CompareResponse(
                    ResultCode::COMPARE_TRUE,
                    '',
                    'foo',
                ),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new CompareRequest(
                        'foo',
                        Filters::equal('foo', 'bar'),
                    ),
                ),
                ResultCode::COMPARE_TRUE,
                'foo',
            ),
        );
    }

    public function test_it_should_get_a_modify_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new ModifyResponse(0, '', 'foo'),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new ModifyRequest('foo', Change::replace('foo', 'bar')),
                ),
                0,
                'foo',
            ),
        );
    }

    public function test_it_should_get_a_modify_dn_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new ModifyDnResponse(0, '', 'foo'),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new ModifyDnRequest('foo', 'cn=bar', true),
                ),
                0,
                'foo',
            ),
        );
    }

    public function test_it_should_get_an_extended_response_that_names_no_oid(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new ExtendedResponse(new LdapResult(0, '', 'foo')),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new ExtendedRequest('1.2.3.4', 'bar'),
                ),
                0,
                'foo',
            ),
        );
    }

    public function test_it_should_get_a_delete_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new DeleteResponse(0, '', 'foo'),
            ),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(
                    1,
                    new DeleteRequest('foo'),
                ),
                0,
                'foo',
            ),
        );
    }

    public function test_it_should_get_a_search_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(1, new SearchResultDone(0, '', 'foo')),
            $this->subject->getStandardResponse(
                new LdapMessageRequest(1, new SearchRequest(Filters::present('objectClass'))),
                0,
                'foo',
            ),
        );
    }

    #[DataProvider('provideMatchedDnWriteResponseCases')]
    public function test_matched_dn_overrides_request_dn_for_write_responses(
        LdapMessageRequest $message,
        ResponseInterface $expectedResponse,
    ): void {
        $actual = $this->subject->getStandardResponse(
            $message,
            ResultCode::NO_SUCH_OBJECT,
            '',
            new Dn('dc=example,dc=com'),
        );

        self::assertEquals(
            $expectedResponse,
            $actual->getResponse(),
        );
    }

    /**
     * @return array<string, array{LdapMessageRequest, ResponseInterface}>
     */
    public static function provideMatchedDnWriteResponseCases(): array
    {
        return [
            'delete' => [
                new LdapMessageRequest(1, new DeleteRequest('cn=Missing,dc=example,dc=com')),
                new DeleteResponse(ResultCode::NO_SUCH_OBJECT, 'dc=example,dc=com', ''),
            ],
            'modify' => [
                new LdapMessageRequest(
                    1,
                    new ModifyRequest('cn=Missing,dc=example,dc=com', Change::replace('cn', 'x')),
                ),
                new ModifyResponse(ResultCode::NO_SUCH_OBJECT, 'dc=example,dc=com', ''),
            ],
            'modifyDn' => [
                new LdapMessageRequest(
                    1,
                    new ModifyDnRequest('cn=Missing,dc=example,dc=com', 'cn=other', true),
                ),
                new ModifyDnResponse(ResultCode::NO_SUCH_OBJECT, 'dc=example,dc=com', ''),
            ],
        ];
    }

    public function test_matched_dn_is_passed_through_for_any_result_code(): void
    {
        $actual = $this->subject->getStandardResponse(
            new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=example,dc=com')),
            ResultCode::ENTRY_ALREADY_EXISTS,
            '',
            new Dn('dc=example,dc=com'),
        );

        self::assertEquals(
            new DeleteResponse(
                ResultCode::ENTRY_ALREADY_EXISTS,
                'dc=example,dc=com',
                '',
            ),
            $actual->getResponse(),
        );
    }

    public function test_it_should_get_an_extended_error_response(): void
    {
        self::assertEquals(
            new LdapMessageResponse(
                0,
                new ExtendedResponse(new LdapResult(
                    ResultCode::PROTOCOL_ERROR,
                    '',
                    'foo',
                )),
            ),
            $this->subject->getExtendedError(
                'foo',
                ResultCode::PROTOCOL_ERROR,
            ),
        );
    }

    public function test_standard_response_threads_through_response_controls(): void
    {
        $control = new PagingControl(
            42,
            'cookie',
        );

        $actual = $this->subject->getStandardResponse(
            new LdapMessageRequest(1, new DeleteRequest('cn=foo,dc=example,dc=com')),
            ResultCode::SUCCESS,
            '',
            null,
            $control,
        );

        self::assertSame(
            [$control],
            $actual->controls()->toArray(),
        );
    }

    public function test_extended_error_threads_through_response_controls(): void
    {
        $control = new PagingControl(
            42,
            'cookie',
        );

        $actual = $this->subject->getExtendedError(
            'foo',
            ResultCode::PROTOCOL_ERROR,
            null,
            $control,
        );

        self::assertSame(
            [$control],
            $actual->controls()->toArray(),
        );
    }
}
