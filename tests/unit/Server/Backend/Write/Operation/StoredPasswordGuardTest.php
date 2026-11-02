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
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Server\AccessControl\Subject\Subject;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\Operation\StoredPasswordGuard;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\BindToken;
use FreeDSx\Ldap\Server\Token\ManagerToken;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use PHPUnit\Framework\TestCase;

final class StoredPasswordGuardTest extends TestCase
{
    private const USER_DN = 'cn=user,dc=foo,dc=bar';

    private const ADMIN_DN = 'cn=admin,dc=foo,dc=bar';

    private const PRE_HASHED = '{SSHA}c2FsdGVkaGFzaA==';

    private const OVER_THE_LIMITS = '{CRYPT}$6$rounds=2000000$saltsaltsalt$hash';

    private StoredPasswordGuard $subject;

    protected function setUp(): void
    {
        $this->subject = new StoredPasswordGuard(
            new PasswordHashService(hashCost: 4),
            administrators: Subject::dn(self::ADMIN_DN),
        );
    }

    public function test_a_cleartext_password_from_any_writer_is_storable(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertStorable(
            $this->userWith('secret'),
            [],
            $this->contextFor(self::USER_DN),
        );
    }

    public function test_a_pre_hashed_password_from_a_writer_who_is_not_an_administrator_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage('A pre-hashed "userPassword" value is accepted from administrators only.');

        $this->subject->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [],
            $this->contextFor(self::USER_DN),
        );
    }

    public function test_a_pre_hashed_password_from_an_administrator_is_storable(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [],
            $this->contextFor(self::ADMIN_DN),
        );
    }

    public function test_a_pre_hashed_password_from_the_manager_is_storable(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [],
            new WriteContext(
                new ManagerToken(new Dn('cn=manager')),
                new ControlBag(),
            ),
        );
    }

    public function test_a_pre_hashed_password_from_a_system_write_is_storable(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [],
            WriteContext::system(
                $this->tokenFor(self::USER_DN),
                new ControlBag(),
            ),
        );
    }

    public function test_a_pre_hashed_password_from_anyone_is_storable_when_allowed(): void
    {
        $this->expectNotToPerformAssertions();

        (new StoredPasswordGuard(
            new PasswordHashService(hashCost: 4),
            allowPreHashed: true,
        ))->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [],
            $this->contextFor(self::USER_DN),
        );
    }

    public function test_a_pre_hashed_password_the_entry_already_held_is_kept_without_an_administrator(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertStorable(
            $this->userWith(self::PRE_HASHED),
            [self::PRE_HASHED],
            $this->contextFor(self::USER_DN),
        );
    }

    public function test_a_pre_hashed_password_over_the_hash_limits_is_refused_even_from_a_system_write(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage(
            'A pre-hashed "userPassword" value asks for more work than the configured hash limits allow.',
        );

        $this->subject->assertStorable(
            $this->userWith(self::OVER_THE_LIMITS),
            [],
            WriteContext::system(
                $this->tokenFor(self::ADMIN_DN),
                new ControlBag(),
            ),
        );
    }

    public function test_more_password_values_than_allowed_are_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);
        $this->expectExceptionMessage('The attribute "userPassword" holds more values than the 1 allowed.');

        $this->subject->assertStorable(
            $this->userWith(
                'first',
                'second',
            ),
            [],
            WriteContext::system(
                $this->tokenFor(self::ADMIN_DN),
                new ControlBag(),
            ),
        );
    }

    public function test_password_values_held_under_an_option_count_toward_the_limit(): void
    {
        $entry = $this->userWith('first');
        $entry->add(new Attribute(
            'userPassword;x-other',
            'second',
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->subject->assertStorable(
            $entry,
            [],
            $this->contextFor(self::ADMIN_DN),
        );
    }

    public function test_a_raised_limit_allows_more_password_values(): void
    {
        $this->expectNotToPerformAssertions();

        (new StoredPasswordGuard(
            new PasswordHashService(hashCost: 4),
            maxValues: 2,
        ))->assertStorable(
            $this->userWith(
                'first',
                'second',
            ),
            [],
            $this->contextFor(self::USER_DN),
        );
    }

    private function userWith(string ...$passwords): Entry
    {
        return new Entry(
            new Dn(self::USER_DN),
            new Attribute('cn', 'user'),
            new Attribute('userPassword', ...$passwords),
        );
    }

    private function contextFor(string $dn): WriteContext
    {
        return new WriteContext(
            $this->tokenFor($dn),
            new ControlBag(),
        );
    }

    private function tokenFor(string $dn): TokenInterface
    {
        return new BindToken(AuthzId::fromDn(new Dn($dn)));
    }
}
