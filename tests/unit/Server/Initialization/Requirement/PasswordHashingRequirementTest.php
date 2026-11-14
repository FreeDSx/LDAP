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

namespace Tests\Unit\FreeDSx\Ldap\Server\Initialization\Requirement;

use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Server\Config\PasswordHashing;
use FreeDSx\Ldap\Server\Initialization\Requirement\PasswordHashingRequirement;
use PHPUnit\Framework\TestCase;

use function constant;
use function defined;

final class PasswordHashingRequirementTest extends TestCase
{
    public function test_bcrypt_hashing_is_met(): void
    {
        $this->expectNotToPerformAssertions();

        (new PasswordHashingRequirement(PasswordHashing::bcrypt()))->assertMet();
    }

    public function test_argon2_hashing_is_refused_when_this_php_build_cannot_hash_it(): void
    {
        if (defined('PASSWORD_ARGON2ID')) {
            self::markTestSkipped('This PHP build hashes argon2id.');
        }

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('This PHP build cannot hash argon2id');

        (new PasswordHashingRequirement(PasswordHashing::argon2id()))->assertMet();
    }

    public function test_argon2_hashing_on_one_thread_is_met_when_this_php_build_hashes_it(): void
    {
        $this->requireArgon2();

        $this->expectNotToPerformAssertions();

        (new PasswordHashingRequirement(PasswordHashing::argon2id(threads: 1)))->assertMet();
    }

    public function test_argon2_hashing_on_several_threads_is_refused_under_libsodium(): void
    {
        $this->requireArgon2Provider('sodium');

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('This PHP build hashes argon2id with libsodium, which supports one thread only.');

        (new PasswordHashingRequirement(PasswordHashing::argon2id(threads: 2)))->assertMet();
    }

    public function test_argon2_hashing_on_several_threads_is_met_under_libargon2(): void
    {
        $this->requireArgon2Provider('standard');

        $this->expectNotToPerformAssertions();

        (new PasswordHashingRequirement(PasswordHashing::argon2id(threads: 2)))->assertMet();
    }

    private function requireArgon2(): void
    {
        if (!defined('PASSWORD_ARGON2ID')) {
            self::markTestSkipped('This PHP build cannot hash argon2id.');
        }
    }

    private function requireArgon2Provider(string $provider): void
    {
        $this->requireArgon2();

        if (constant('PASSWORD_ARGON2_PROVIDER') !== $provider) {
            self::markTestSkipped('This PHP build hashes argon2id with another provider.');
        }
    }
}
