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

namespace Tests\Unit\FreeDSx\Ldap\Server\Config;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashScheme;
use FreeDSx\Ldap\Server\Config\PasswordConfig;
use FreeDSx\Ldap\Server\Config\PasswordHashing;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\DefaultPasswordQualityChecker;
use FreeDSx\Ldap\Server\PasswordPolicy\QualityCheck\PasswordQualityCheckerInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use PHPUnit\Framework\TestCase;

final class PasswordConfigTest extends TestCase
{
    private PasswordConfig $subject;

    protected function setUp(): void
    {
        $this->subject = new PasswordConfig();
    }

    public function test_a_password_value_limit_below_one_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);

        // @phpstan-ignore argument.type
        $this->subject->setMaxPasswordValues(0);
    }

    public function test_no_password_policy_source_is_configured_by_default(): void
    {
        self::assertNull($this->subject->getPolicy());
        self::assertNull($this->subject->getDefaultPolicyDn());
    }

    public function test_the_in_memory_policy_is_retained(): void
    {
        $policy = new PasswordPolicy(quality: new PasswordQualityRules(minLength: 8));

        $this->subject->setPolicy($policy);

        self::assertSame(
            $policy,
            $this->subject->getPolicy(),
        );
    }

    public function test_the_default_policy_dn_is_retained(): void
    {
        $dn = new Dn('cn=default,ou=policies,dc=example,dc=com');

        $this->subject->setDefaultPolicyDn($dn);

        self::assertSame(
            $dn,
            $this->subject->getDefaultPolicyDn(),
        );
    }

    public function test_new_passwords_are_hashed_with_argon2id_at_7_mib_and_five_passes_by_default(): void
    {
        $hashing = $this->subject->getHashing();

        self::assertSame(
            [
                PasswordHashScheme::Argon2,
                7168,
                5,
                1,
            ],
            [
                $hashing->getScheme(),
                $hashing->getArgon2Memory(),
                $hashing->getArgon2Passes(),
                $hashing->getArgon2Threads(),
            ],
        );
    }

    public function test_the_hashing_given_to_the_constructor_is_retained(): void
    {
        $hashing = PasswordHashing::ssha();

        self::assertSame(
            $hashing,
            (new PasswordConfig(hashing: $hashing))->getHashing(),
        );
    }

    public function test_setting_the_hashing_is_round_tripped(): void
    {
        $hashing = PasswordHashing::ssha();

        $this->subject->setHashing($hashing);

        self::assertSame(
            $hashing,
            $this->subject->getHashing(),
        );
    }

    public function test_the_quality_checker_defaults_to_the_built_in_checker(): void
    {
        self::assertInstanceOf(
            DefaultPasswordQualityChecker::class,
            $this->subject->getQualityChecker(),
        );
    }

    public function test_setting_the_quality_checker_is_round_tripped(): void
    {
        $checker = $this->createMock(PasswordQualityCheckerInterface::class);

        $this->subject->setQualityChecker($checker);

        self::assertSame(
            $checker,
            $this->subject->getQualityChecker(),
        );
    }
}
