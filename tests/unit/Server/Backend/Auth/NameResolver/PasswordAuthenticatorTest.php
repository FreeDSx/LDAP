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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Auth\NameResolver\BindNameResolverInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticator;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Sasl\Mechanism\MechanismName;
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

    public function test_throws_when_entry_not_found(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject(null)->authenticate('cn=Unknown,dc=example,dc=com', 'secret');
    }

    public function test_throws_when_entry_has_no_user_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Alice,dc=example,dc=com', 'secret');
    }

    public function test_returns_token_for_correct_plain_text_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        $token = $this->subject($entry)->authenticate('cn=Alice,dc=example,dc=com', 'secret');

        self::assertInstanceOf(BindToken::class, $token);
        self::assertSame('cn=Alice,dc=example,dc=com', $token->getUsername());
        self::assertSame('cn=Alice,dc=example,dc=com', $token->getResolvedDn()->toString());
    }

    public function test_throws_for_wrong_plain_text_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Alice,dc=example,dc=com', 'wrong');
    }

    public function test_returns_token_for_correct_sha_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        $token = $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'mypassword');

        self::assertInstanceOf(BindToken::class, $token);
    }

    public function test_throws_for_wrong_sha_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'wrong');
    }

    public function test_returns_token_for_correct_ssha_password(): void
    {
        $salt = 'salt';
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        $token = $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'mypassword');

        self::assertInstanceOf(BindToken::class, $token);
    }

    public function test_throws_for_wrong_ssha_password(): void
    {
        $salt = 'salt';
        $hashed = '{SSHA}' . base64_encode(sha1('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'wrong');
    }

    public function test_returns_token_for_correct_md5_password(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        $token = $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'mypassword');

        self::assertInstanceOf(BindToken::class, $token);
    }

    public function test_throws_for_wrong_md5_password(): void
    {
        $hashed = '{MD5}' . base64_encode(md5('mypassword', true));
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'wrong');
    }

    public function test_returns_token_for_correct_smd5_password(): void
    {
        $salt = 'salt';
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        $token = $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'mypassword');

        self::assertInstanceOf(BindToken::class, $token);
    }

    public function test_throws_for_wrong_smd5_password(): void
    {
        $salt = 'salt';
        $hashed = '{SMD5}' . base64_encode(md5('mypassword' . $salt, true) . $salt);
        $entry = new Entry(
            new Dn('cn=Test,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::expectException(OperationException::class);
        self::expectExceptionCode(ResultCode::INVALID_CREDENTIALS);

        $this->subject($entry)->authenticate('cn=Test,dc=example,dc=com', 'wrong');
    }

    public function test_resolved_dn_is_the_entry_dn_not_the_raw_bind_name(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        $token = $this->subject($entry)->authenticate('uid=alice', 'secret');

        self::assertSame('uid=alice', $token->getUsername());
        self::assertSame('cn=Alice,dc=example,dc=com', $token->getResolvedDn()->toString());
    }

    public function test_get_sasl_identity_returns_null_when_entry_not_found(): void
    {
        self::assertNull(
            $this->subject()->getSaslIdentity('unknown', MechanismName::SCRAM_SHA256),
        );
    }

    public function test_get_sasl_identity_returns_null_when_entry_has_no_user_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('cn', 'Alice'),
        );

        self::assertNull(
            $this->subject($entry)->getSaslIdentity('cn=Alice,dc=example,dc=com', MechanismName::SCRAM_SHA256),
        );
    }

    public function test_get_sasl_identity_returns_identity_with_plaintext_password(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        $identity = $this->subject($entry)->getSaslIdentity('alice', MechanismName::SCRAM_SHA256);

        self::assertInstanceOf(SaslIdentity::class, $identity);
        self::assertSame('secret', $identity->password);
        self::assertSame('cn=Alice,dc=example,dc=com', $identity->resolvedDn->toString());
    }

    /**
     * A mechanism keying on the stored value would otherwise make the hash itself the password.
     */
    public function test_get_sasl_identity_returns_null_for_a_hashed_password(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('secret', true));
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        self::assertNull(
            $this->subject($entry)->getSaslIdentity('alice', MechanismName::SCRAM_SHA256),
        );
    }

    /**
     * PLAIN verifies the presented password against the stored value, so a hash is still usable there.
     */
    public function test_get_sasl_identity_returns_a_hashed_password_for_plain(): void
    {
        $hashed = '{SHA}' . base64_encode(sha1('secret', true));
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', $hashed),
        );

        $identity = $this->subject($entry)->getSaslIdentity('alice', MechanismName::PLAIN);

        self::assertInstanceOf(SaslIdentity::class, $identity);
        self::assertSame(
            $hashed,
            $identity->password,
        );
    }

    public function test_get_sasl_identity_uses_the_same_resolver_as_authenticate(): void
    {
        $entry = new Entry(
            new Dn('cn=Alice,dc=example,dc=com'),
            new Attribute('userPassword', 'secret'),
        );

        $this->mockResolver
            ->expects(self::once())
            ->method('resolve')
            ->willReturn($entry);

        $identity = (new PasswordAuthenticator(
            $this->mockResolver,
            $this->mockBackend,
        ))->getSaslIdentity('alice', MechanismName::SCRAM_SHA256);

        self::assertInstanceOf(SaslIdentity::class, $identity);
    }

    private function subject(?Entry $resolvedEntry = null): PasswordAuthenticator
    {
        $this->mockResolver
            ->method('resolve')
            ->with(
                self::isType('string'),
                $this->mockBackend,
            )
            ->willReturn($resolvedEntry);

        return new PasswordAuthenticator(
            $this->mockResolver,
            $this->mockBackend,
        );
    }
}
