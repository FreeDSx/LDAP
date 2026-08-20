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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordResetGate;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;

final class PasswordResetGateTest extends TestCase
{
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private PasswordResetGate $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordResetGate();
    }

    public function test_unbind_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new UnbindRequest(),
            $this->token(),
        ));
    }

    public function test_abandon_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new AbandonRequest(1),
            $this->token(),
        ));
    }

    public function test_password_modify_extended_op_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new ExtendedRequest(ExtendedRequest::OID_PWD_MODIFY),
            $this->token(),
        ));
    }

    /**
     * draft-behera-11 §8.1.2.2 names StartTLS, and RFC 3062 §4 wants password modify run under confidentiality.
     */
    public function test_start_tls_extended_op_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new ExtendedRequest(ExtendedRequest::OID_START_TLS),
            $this->token(),
        ));
    }

    public function test_other_extended_op_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
            $this->token(),
        ));
    }

    public function test_self_password_only_modify_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new ModifyRequest(
                self::USER_DN,
                Change::replace('userPassword', 'a-fresh-password'),
            ),
            $this->token(),
        ));
    }

    public function test_self_password_delete_add_modify_is_permitted(): void
    {
        self::assertTrue($this->subject->isPermitted(
            new ModifyRequest(
                self::USER_DN,
                Change::delete('userPassword', 'old'),
                Change::add('userPassword', 'a-fresh-password'),
            ),
            $this->token(),
        ));
    }

    public function test_self_modify_touching_another_attribute_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new ModifyRequest(
                self::USER_DN,
                Change::replace('userPassword', 'a-fresh-password'),
                Change::replace('description', 'sneaky'),
            ),
            $this->token(),
        ));
    }

    public function test_password_modify_on_another_dn_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new ModifyRequest(
                'cn=other,dc=foo,dc=bar',
                Change::replace('userPassword', 'a-fresh-password'),
            ),
            $this->token(),
        ));
    }

    public function test_empty_modify_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new ModifyRequest(self::USER_DN),
            $this->token(),
        ));
    }

    public function test_search_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new SearchRequest(Filters::present('objectClass')),
            $this->token(),
        ));
    }

    public function test_compare_is_not_permitted(): void
    {
        self::assertFalse($this->subject->isPermitted(
            new CompareRequest(
                self::USER_DN,
                Filters::equal('cn', 'user'),
            ),
            $this->token(),
        ));
    }

    private function token(): BindToken
    {
        return BindToken::fromDn(
            self::USER_DN,
        );
    }
}
