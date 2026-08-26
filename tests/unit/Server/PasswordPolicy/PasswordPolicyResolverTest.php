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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicy;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyResolver;
use FreeDSx\Ldap\Server\PasswordPolicy\Rules\PasswordQualityRules;
use FreeDSx\Ldap\Schema\Definition\ObjectClassOid;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;
use FreeDSx\Ldap\Server\Subentry\GoverningSubentryResolver;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationEvaluator;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PasswordPolicyResolverTest extends TestCase
{
    use ServerContainerTrait;

    private const USER_DN = 'uid=alice,dc=example,dc=com';

    private const SUBENTRY_DN = 'cn=subentry-policy,ou=policies,dc=example,dc=com';

    private const DEFAULT_DN = 'cn=default,ou=policies,dc=example,dc=com';

    /**
     * @var array<string, int> DN string → number of get() calls
     */
    private array $getCalls = [];

    public function test_returns_null_when_no_source_configured(): void
    {
        $resolver = new PasswordPolicyResolver(
            $this->backend(),
            defaultPolicyDn: null,
            inMemoryFallback: null,
        );

        self::assertNull($resolver->resolveFor($this->userEntry()));
    }

    public function test_falls_back_to_in_memory_policy_when_no_dn_configured(): void
    {
        $fallback = new PasswordPolicy(quality: new PasswordQualityRules(minLength: 8));

        $resolver = new PasswordPolicyResolver(
            $this->backend(),
            defaultPolicyDn: null,
            inMemoryFallback: $fallback,
        );

        self::assertSame(
            $fallback,
            $resolver->resolveFor($this->userEntry()),
        );
    }

    public function test_resolves_from_default_dn_when_user_has_no_subentry(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '10'],
        );
        $backend = $this->backend([self::DEFAULT_DN => $defaultEntry]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor($this->userEntry());

        self::assertNotNull($resolved);
        self::assertSame(
            10,
            $resolved->quality->minLength,
        );
    }

    public function test_resolves_from_user_subentry_when_present(): void
    {
        $subentryEntry = $this->policyEntry(
            self::SUBENTRY_DN,
            ['pwdMinLength' => '12'],
        );
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = $this->backend([
            self::SUBENTRY_DN => $subentryEntry,
            self::DEFAULT_DN => $defaultEntry,
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor(
            $this->userEntry(['pwdPolicySubentry' => self::SUBENTRY_DN]),
        );

        self::assertNotNull($resolved);
        self::assertSame(
            12,
            $resolved->quality->minLength,
        );
    }

    public function test_missing_subentry_dn_falls_through_to_default(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = $this->backend([
            self::DEFAULT_DN => $defaultEntry,
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolved = $resolver->resolveFor(
            $this->userEntry(['pwdPolicySubentry' => 'cn=missing,ou=policies,dc=example,dc=com']),
        );

        self::assertNotNull($resolved);
        self::assertSame(
            6,
            $resolved->quality->minLength,
        );
    }

    /**
     * Nothing is cached between operations, so an edited policy entry takes effect immediately.
     */
    public function test_each_resolution_re_reads_the_policy_entry(): void
    {
        $defaultEntry = $this->policyEntry(
            self::DEFAULT_DN,
            ['pwdMinLength' => '6'],
        );
        $backend = $this->backend([self::DEFAULT_DN => $defaultEntry]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
        );

        $resolver->resolveFor($this->userEntry());
        $resolver->resolveFor($this->userEntry());
        $resolver->resolveFor($this->userEntry());

        self::assertSame(
            3,
            $this->getCalls[self::DEFAULT_DN] ?? 0,
        );
    }

    public function test_resolves_from_a_governing_subentry_when_the_user_has_no_pointer(): void
    {
        $resolver = new PasswordPolicyResolver(
            $this->backend(),
            defaultPolicyDn: null,
            inMemoryFallback: null,
            subentries: $this->governedBy(['pwdMinLength' => '9']),
        );

        $resolved = $resolver->resolveFor($this->userEntry());

        self::assertNotNull($resolved);
        self::assertSame(
            9,
            $resolved->quality->minLength,
        );
    }

    public function test_the_user_pointer_outranks_a_governing_subentry(): void
    {
        $backend = $this->backend([
            self::SUBENTRY_DN => $this->policyEntry(
                self::SUBENTRY_DN,
                ['pwdMinLength' => '12'],
            ),
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: null,
            inMemoryFallback: null,
            subentries: $this->governedBy(['pwdMinLength' => '9']),
        );

        $resolved = $resolver->resolveFor(
            $this->userEntry(['pwdPolicySubentry' => self::SUBENTRY_DN]),
        );

        self::assertNotNull($resolved);
        self::assertSame(
            12,
            $resolved->quality->minLength,
        );
    }

    public function test_a_governing_subentry_outranks_the_default_dn(): void
    {
        $backend = $this->backend([
            self::DEFAULT_DN => $this->policyEntry(
                self::DEFAULT_DN,
                ['pwdMinLength' => '6'],
            ),
        ]);

        $resolver = new PasswordPolicyResolver(
            $backend,
            defaultPolicyDn: new Dn(self::DEFAULT_DN),
            inMemoryFallback: null,
            subentries: $this->governedBy(['pwdMinLength' => '9']),
        );

        $resolved = $resolver->resolveFor($this->userEntry());

        self::assertNotNull($resolved);
        self::assertSame(
            9,
            $resolved->quality->minLength,
        );
    }

    public function test_a_governing_subentry_without_a_policy_class_is_ignored(): void
    {
        $resolver = new PasswordPolicyResolver(
            $this->backend(),
            defaultPolicyDn: null,
            inMemoryFallback: null,
            subentries: $this->governedBy(policyClass: false),
        );

        self::assertNull($resolver->resolveFor($this->userEntry()));
    }

    /**
     * A real resolver over a backend that hosts one administrative point holding one subentry.
     *
     * @param array<string, string> $extra
     */
    private function governedBy(
        array $extra = [],
        bool $policyClass = true,
    ): GoverningSubentryResolver {
        $objectClasses = $policyClass
            ? [ObjectClassOid::NAME_SUBENTRY, PasswordPolicyOid::NAME_PWD_POLICY]
            : [ObjectClassOid::NAME_SUBENTRY];
        $subentry = Entry::fromArray(
            'cn=policy,dc=example,dc=com',
            [
                'objectClass' => $objectClasses,
                'subtreeSpecification' => '{ }',
                'pwdAttribute' => 'userPassword',
            ] + $extra,
        );

        $backend = $this->createMock(ReadBackendInterface::class);
        $backend->method('get')
            ->willReturnCallback(static fn(Dn $dn): ?Entry => $dn->toString() === 'dc=example,dc=com'
                ? Entry::fromArray(
                    'dc=example,dc=com',
                    ['administrativeRole' => '2.5.23.4'],
                )
                : null);
        $backend->method('search')
            ->willReturn(new EntryStream((static function () use ($subentry): Generator {
                yield $subentry;

                return null;
            })()));

        return new GoverningSubentryResolver(
            $backend,
            new SubtreeSpecificationEvaluator(
                $this->fromContainer(FilterEvaluatorInterface::class),
            ),
        );
    }

    /**
     * A backend stub keyed by DN string that records how many times each DN is fetched.
     *
     * @param array<string, Entry> $entries DN string → entry
     */
    private function backend(array $entries = []): ReadBackendInterface&MockObject
    {
        $backend = $this->createMock(ReadBackendInterface::class);
        $backend->method('get')
            ->willReturnCallback(function (Dn $dn) use ($entries): ?Entry {
                $key = $dn->toString();
                $this->getCalls[$key] = ($this->getCalls[$key] ?? 0) + 1;

                return $entries[$key] ?? null;
            });

        return $backend;
    }

    /**
     * @param array<string, string> $extra
     */
    private function userEntry(array $extra = []): Entry
    {
        return Entry::fromArray(
            self::USER_DN,
            ['uid' => 'alice'] + $extra,
        );
    }

    /**
     * @param array<string, string> $extra
     */
    private function policyEntry(
        string $dn,
        array $extra,
    ): Entry {
        return Entry::fromArray(
            $dn,
            ['pwdAttribute' => 'userPassword'] + $extra,
        );
    }
}
