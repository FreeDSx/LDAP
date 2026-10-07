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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\AssertionEvaluator;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AclRules;
use FreeDSx\Ldap\Server\AccessControl\RuleBasedAccessControl;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\ReadEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Derived\DerivedResolver;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\LinkedLeafWitness;
use FreeDSx\Ldap\Server\Backend\Write\WriteControlEvaluator;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\ServerContainerTrait;

final class WriteControlEvaluatorTest extends TestCase
{
    use ServerContainerTrait;

    private AssertionEvaluator $assertions;

    private ReadEntryInterface&MockObject $storage;

    private Entry $entry;

    protected function setUp(): void
    {
        $this->storage = $this->createMock(ReadEntryInterface::class);
        $this->assertions = new AssertionEvaluator(
            $this->fromContainer(FilterEvaluatorInterface::class),
            $this->createMock(ReadBackendInterface::class),
            new RuleBasedAccessControl(AclRules::fromEmpty()),
            $this->fromContainer(LinkedLeafWitness::class),
        );
        $this->entry = Entry::fromArray(
            'cn=foo,dc=ex,dc=com',
            ['cn' => ['foo'], 'sn' => ['Smith']],
        );
    }

    public function test_a_target_satisfying_the_assertion_is_accepted(): void
    {
        $subject = $this->evaluatorFor(Controls::assertion(Filters::equal('sn', 'Smith')));

        $subject->evaluateTarget($this->entry);

        self::assertNull($subject->preReadEntry());
    }

    public function test_a_target_failing_the_assertion_answers_assertion_failed(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->evaluatorFor(Controls::assertion(Filters::equal('sn', 'Jones')))
            ->evaluateTarget($this->entry);
    }

    public function test_a_pre_read_keeps_a_copy_of_the_target(): void
    {
        $subject = $this->evaluatorFor(new PreReadControl('sn'));

        $subject->evaluateTarget($this->entry);
        $this->entry->get('sn')?->set('Jones');

        self::assertSame(
            ['Smith'],
            $subject->preReadEntry()?->get('sn')?->getValues(),
        );
    }

    public function test_a_post_read_keeps_a_copy_of_the_result(): void
    {
        $subject = $this->evaluatorFor(new PostReadControl('sn'));

        $subject->captureResult($this->entry);
        $this->entry->get('sn')?->set('Jones');

        self::assertSame(
            ['Smith'],
            $subject->postReadEntry()?->get('sn')?->getValues(),
        );
    }

    public function test_an_addition_failing_the_assertion_answers_assertion_failed(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ASSERTION_FAILED);

        $this->evaluatorFor(Controls::assertion(Filters::equal('sn', 'Jones')))
            ->evaluateAddition($this->entry);
    }

    public function test_an_addition_satisfying_the_assertion_is_kept_for_a_post_read(): void
    {
        $subject = $this->evaluatorFor(
            Controls::assertion(Filters::equal('sn', 'Smith')),
            new PostReadControl('sn'),
        );

        $subject->evaluateAddition($this->entry);

        self::assertSame(
            ['Smith'],
            $subject->postReadEntry()?->get('sn')?->getValues(),
        );
    }

    public function test_nothing_is_kept_without_a_read_control(): void
    {
        $subject = $this->evaluatorFor();

        $subject->evaluateTarget($this->entry);
        $subject->captureResult($this->entry);

        self::assertNull($subject->preReadEntry());
        self::assertNull($subject->postReadEntry());
    }

    public function test_a_later_attempt_replaces_what_an_earlier_one_kept(): void
    {
        $subject = $this->evaluatorFor(new PostReadControl('sn'));

        $subject->captureResult($this->entry);
        $subject->captureResult(Entry::fromArray(
            'cn=foo,dc=ex,dc=com',
            ['sn' => ['Jones']],
        ));

        self::assertSame(
            ['Jones'],
            $subject->postReadEntry()?->get('sn')?->getValues(),
        );
    }

    public function test_a_post_read_carries_the_derived_attributes_it_names(): void
    {
        $subject = $this->evaluatorFor(new PostReadControl('entryDN', 'subschemaSubentry'));

        $subject->captureResult($this->entry);
        $kept = $subject->postReadEntry();

        self::assertNotNull($kept);
        self::assertSame(
            ['cn=foo,dc=ex,dc=com'],
            $kept->get('entryDN')?->getValues(),
        );
        self::assertSame(
            ['cn=Subschema'],
            $kept->get('subschemaSubentry')?->getValues(),
        );
    }

    public function test_a_pre_read_selects_the_derived_attributes_with_the_operational_wildcard(): void
    {
        $subject = $this->evaluatorFor(new PreReadControl('+'));

        $subject->evaluateTarget($this->entry);

        self::assertSame(
            ['cn=foo,dc=ex,dc=com'],
            $subject->preReadEntry()?->get('entryDN')?->getValues(),
        );
    }

    public function test_a_read_control_naming_no_derived_attribute_adds_none(): void
    {
        $this->storage
            ->expects(self::never())
            ->method('hasChildren');
        $subject = $this->evaluatorFor(new PostReadControl('sn'));

        $subject->captureResult($this->entry);

        self::assertNull($subject->postReadEntry()?->get('entryDN'));
    }

    public function test_a_post_read_counts_subordinates_on_the_entry_the_write_found(): void
    {
        $this->storage
            ->expects(self::once())
            ->method('hasChildren')
            ->with(self::callback(static fn(Dn $dn): bool => $dn->toString() === 'cn=foo,dc=ex,dc=com'))
            ->willReturn(true);
        $subject = $this->evaluatorFor(new PostReadControl('hasSubordinates'));

        $subject->evaluateTarget($this->entry);
        $subject->captureResult(Entry::fromArray(
            'cn=renamed,dc=ex,dc=com',
            ['cn' => ['renamed']],
        ));

        self::assertSame(
            ['TRUE'],
            $subject->postReadEntry()?->get('hasSubordinates')?->getValues(),
        );
    }

    private function evaluatorFor(Control ...$controls): WriteControlEvaluator
    {
        return new WriteControlEvaluator(
            $this->assertions,
            BindToken::fromDn('cn=foo,dc=ex,dc=com'),
            new ControlBag(...$controls),
            new DerivedResolver($this->storage),
        );
    }
}
