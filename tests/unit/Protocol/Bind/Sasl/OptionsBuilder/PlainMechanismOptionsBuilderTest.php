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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Bind\Sasl\OptionsBuilder\PlainMechanismOptionsBuilder;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordAuthenticatableInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Auth\SaslIdentity;
use FreeDSx\Sasl\Mechanism\MechanismName;
use FreeDSx\Sasl\Options\PlainOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class PlainMechanismOptionsBuilderTest extends TestCase
{
    private PasswordAuthenticatableInterface&MockObject $mockAuthenticator;

    private PlainMechanismOptionsBuilder $subject;

    protected function setUp(): void
    {
        $this->mockAuthenticator = $this->createMock(PasswordAuthenticatableInterface::class);
        $this->subject = new PlainMechanismOptionsBuilder($this->mockAuthenticator);
    }

    public function test_it_builds_options_with_a_validate_callable(): void
    {
        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);

        self::assertInstanceOf(PlainOptions::class, $options);
        self::assertIsCallable($options->getValidate());
    }

    public function test_the_validate_callable_returns_true_for_correct_credentials(): void
    {
        $identity = new SaslIdentity('12345', new Dn('cn=user,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->expects(self::once())
            ->method('getSaslIdentity')
            ->with('cn=user,dc=foo,dc=bar', MechanismName::PLAIN)
            ->willReturn($identity);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        self::assertInstanceOf(PlainOptions::class, $options);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $result = $validate('authzid', 'cn=user,dc=foo,dc=bar', '12345');

        self::assertTrue($result);
    }

    public function test_the_validate_callable_returns_false_when_identity_is_not_found(): void
    {
        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn(null);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        self::assertInstanceOf(PlainOptions::class, $options);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $result = $validate(null, 'unknown', 'wrong');

        self::assertFalse($result);
    }

    public function test_the_validate_callable_returns_false_for_wrong_password(): void
    {
        $identity = new SaslIdentity('correct', new Dn('cn=user,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        self::assertInstanceOf(PlainOptions::class, $options);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $result = $validate(null, 'cn=user,dc=foo,dc=bar', 'wrong');

        self::assertFalse($result);
    }

    public function test_it_builds_the_same_options_regardless_of_received_bytes(): void
    {
        $optionsWithNull = $this->subject->buildOptions(null, MechanismName::PLAIN);
        $optionsWithBytes = $this->subject->buildOptions('some-bytes', MechanismName::PLAIN);

        self::assertInstanceOf(PlainOptions::class, $optionsWithNull);
        self::assertInstanceOf(PlainOptions::class, $optionsWithBytes);
    }

    public function test_get_resolved_dn_is_populated_after_successful_validation(): void
    {
        $identity = new SaslIdentity('12345', new Dn('cn=user,dc=foo,dc=bar'));

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn($identity);

        $options = $this->subject->buildOptions(null, MechanismName::PLAIN);
        assert($options instanceof PlainOptions);
        $validate = $options->getValidate();
        assert(is_callable($validate));
        $validate('authzid', 'cn=user,dc=foo,dc=bar', '12345');

        self::assertSame(
            'cn=user,dc=foo,dc=bar',
            $this->subject->getResolvedDn()?->toString(),
        );
    }

    public function test_a_name_resolving_to_nothing_is_refused_at_the_cost_of_a_comparison(): void
    {
        $hashService = $this->createMock(PasswordHashService::class);
        $hashService->expects(self::once())
            ->method('verifyDummy')
            ->with('wrong');

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn(null);

        $subject = new PlainMechanismOptionsBuilder(
            $this->mockAuthenticator,
            $hashService,
        );
        $options = $subject->buildOptions(null, MechanismName::PLAIN);
        assert($options instanceof PlainOptions);
        $validate = $options->getValidate();
        assert(is_callable($validate));

        self::assertFalse($validate(
            null,
            'unknown',
            'wrong',
        ));
    }

    public function test_a_resolved_name_is_not_charged_a_dummy_comparison(): void
    {
        $hashService = $this->createMock(PasswordHashService::class);
        $hashService->expects(self::never())
            ->method('verifyDummy');
        $hashService->method('verify')
            ->willReturn(false);

        $this->mockAuthenticator
            ->method('getSaslIdentity')
            ->willReturn(new SaslIdentity(
                'correct',
                new Dn('cn=user,dc=foo,dc=bar'),
            ));

        $subject = new PlainMechanismOptionsBuilder(
            $this->mockAuthenticator,
            $hashService,
        );
        $options = $subject->buildOptions(null, MechanismName::PLAIN);
        assert($options instanceof PlainOptions);
        $validate = $options->getValidate();
        assert(is_callable($validate));

        self::assertFalse($validate(
            null,
            'cn=user,dc=foo,dc=bar',
            'wrong',
        ));
    }
}
