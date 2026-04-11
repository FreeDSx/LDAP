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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Auth\NameResolver;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PasswordAuthenticatorTest extends TestCase
{
    private BindNameResolverInterface&MockObject $mockResolver;

    private LdapBackendInterface&MockObject $mockBackend;

    protected function setUp(): void
    {
        $this->mockResolver = $this->createMock(BindNameResolverInterface::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
    }

    private function subject(?Entry $resolvedEntry = null): PasswordAuthenticator
    {
        $this->mockResolver
            ->method('resolve')
            ->with(self::isType('string'), $this->mockBackend)
            ->willReturn($resolvedEntry);

        return new PasswordAuthenticator(
            $this->mockResolver,
            $this->mockBackend
        );
    }

    public function test_returns_false_when_entry_not_found(): void
    {
        self::assertFalse(
            $this->subject(null)->verifyPassword('cn=Unknown,dc=example,dc=com', 'secret')
        );
    }

    public function test_returns_false_when_entry_has_no_user_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Alice,dc=example,dc=com', 'secret')
        );
    }

    public function test_returns_true_for_correct_plain_text_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        self::assertTrue(
            $this->subject($entry)->verifyPassword('cn=Alice,dc=example,dc=com', 'secret')
        );
    }

    public function test_returns_false_for_wrong_plain_text_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Alice,dc=example,dc=com', 'wrong')
        );
    }

    public function test_returns_true_for_correct_sha_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertTrue(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'mypassword')
        );
    }

    public function test_returns_false_for_wrong_sha_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'wrong')
        );
    }

    public function test_returns_true_for_correct_ssha_password(): void
    {
        $salt = 'salt';
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertTrue(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'mypassword')
        );
    }

    public function test_returns_false_for_wrong_ssha_password(): void
    {
        $salt = 'salt';
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'wrong')
        );
    }

    public function test_returns_true_for_correct_md5_password(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertTrue(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'mypassword')
        );
    }

    public function test_returns_false_for_wrong_md5_password(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'wrong')
        );
    }

    public function test_returns_true_for_correct_smd5_password(): void
    {
        $salt = 'salt';
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertTrue(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'mypassword')
        );
    }

    public function test_returns_false_for_wrong_smd5_password(): void
    {
        $salt = 'salt';
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertFalse(
            $this->subject($entry)->verifyPassword('cn=Test,dc=example,dc=com', 'wrong')
        );
    }

    public function test_get_password_returns_null_when_entry_not_found(): void
    {
        self::assertNull(
            $this->subject()->getPassword('unknown', 'SCRAM-SHA-256')
        );
    }

    public function test_get_password_returns_null_when_entry_has_no_user_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        self::assertNull(
            $this->subject($entry)->getPassword('cn=Alice,dc=example,dc=com', 'SCRAM-SHA-256')
        );
    }

    public function test_get_password_returns_raw_value_for_plaintext_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        self::assertSame(
            'secret',
            $this->subject($entry)->getPassword('cn=Alice,dc=example,dc=com', 'SCRAM-SHA-256')
        );
    }

    public function test_get_password_returns_raw_value_for_hashed_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('secret', true));
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertSame(
            $hashed,
            $this->subject($entry)->getPassword('cn=Alice,dc=example,dc=com', 'SCRAM-SHA-256')
        );
    }
}
