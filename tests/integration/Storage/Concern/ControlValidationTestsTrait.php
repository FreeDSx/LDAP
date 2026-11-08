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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ReadEntry\PostReadControl;
use FreeDSx\Ldap\Control\ReadEntry\PreReadControl;
use FreeDSx\Ldap\Control\Sync\SyncStateControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * How the controls on a request are vetted before it runs: criticality, repeats, and malformed values.
 */
trait ControlValidationTestsTrait
{
    /**
     * @return iterable<string, array{RequestInterface, Control}>
     */
    public static function inappropriateCriticalControls(): iterable
    {
        // RFC 4527 §3.1 leaves pre-read to the operations with a before image, which an add has not.
        yield 'pre-read on an add' => [
            Operations::add(Entry::create(
                'cn=ctl,dc=foo,dc=bar',
                ['objectClass' => 'inetOrgPerson', 'cn' => 'ctl', 'sn' => 'Ctl'],
            )),
            new PreReadControl('cn'),
        ];
        // RFC 4527 §3.2: a deleted entry has no after image, so post-read does not suit a delete.
        yield 'post-read on a delete' => [
            Operations::delete('cn=ctl,dc=foo,dc=bar'),
            new PostReadControl('cn'),
        ];
        yield 'pre-read on a compare' => [
            Operations::compare('cn=alice,ou=people,dc=foo,dc=bar', 'sn', 'Smith'),
            new PreReadControl('cn'),
        ];
        yield 'subtree delete on a modify' => [
            Operations::modify(
                'cn=alice,ou=people,dc=foo,dc=bar',
                Change::replace('description', 'ctl'),
            ),
            new Control(Control::OID_SUBTREE_DELETE),
        ];
    }

    /**
     * RFC 4511 §4.1.11: a control the operation does not take must fail it rather than be dropped.
     */
    #[DataProvider('inappropriateCriticalControls')]
    public function testACriticalControlTheOperationDoesNotTakeIsRefused(
        RequestInterface $request,
        Control $control,
    ): void {
        $this->authenticateAdmin();

        try {
            $this->ldapClient()->sendAndReceive(
                $request,
                $control->setCriticality(true),
            );
            self::fail('The critical control should have failed the operation.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }
    }

    #[DataProvider('repeatedControlProvider')]
    public function testASearchCarryingTheSameControlTwiceIsRefusedWithAProtocolError(
        Control $first,
        Control $second,
    ): void {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
                $first,
                $second,
            );
            self::fail('A search carrying the same control twice should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }
    }

    /**
     * @return iterable<string, array{Control, Control}>
     */
    public static function repeatedControlProvider(): iterable
    {
        yield 'a matching assertion, then a failing one' => [
            Controls::assertion(Filters::equal('dc', 'foo')),
            Controls::assertion(Filters::equal('dc', 'nope')),
        ];
        yield 'a failing assertion, then a matching one' => [
            Controls::assertion(Filters::equal('dc', 'nope')),
            Controls::assertion(Filters::equal('dc', 'foo')),
        ];
        yield 'two paging controls' => [
            Controls::paging(2),
            Controls::paging(100),
        ];
    }

    #[DataProvider('malformedControlProvider')]
    public function testAMalformedControlValueIsAnsweredWithoutEndingTheSession(Control $control): void
    {
        $this->authenticateUser();

        $search = Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        try {
            $this->ldapClient()->search(
                $search,
                $control,
            );
            self::fail('The malformed control value should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        }

        // The same connection must still serve requests, which is the whole point of answering rather than closing.
        self::assertCount(
            8,
            $this->ldapClient()->search($search),
        );
    }

    /**
     * @return iterable<string, array{Control}>
     */
    public static function malformedControlProvider(): iterable
    {
        yield 'a paging value that is not a paging control' => [new Control(
            Control::OID_PAGING,
            false,
            'not-a-paging-control',
        )];
        yield 'an empty paging value' => [new Control(
            Control::OID_PAGING,
            false,
            '',
        )];
        yield 'an empty paging value on a critical control' => [new Control(
            Control::OID_PAGING,
            true,
            '',
        )];
        // Raw BER for 2^64, as encoding an integer this wide needs the GMP extension.
        yield 'a paging size wider than an integer' => [new Control(
            Control::OID_PAGING,
            false,
            "\x30\x0d\x02\x09\x01" . str_repeat("\x00", 8) . "\x04\x00",
        )];
        yield 'a sync request mode wider than an integer' => [new Control(
            Control::OID_SYNC_REQUEST,
            false,
            "\x30\x0b\x0a\x09\x01" . str_repeat("\x00", 8),
        )];
    }

    #[DataProvider('controlsOnlyAServerSends')]
    public function testANonCriticalControlOnlyAServerSendsIsIgnored(Control $control): void
    {
        $this->authenticateUser();

        self::assertCount(
            8,
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                $control->setCriticality(false),
            ),
        );
    }

    #[DataProvider('controlsOnlyAServerSends')]
    public function testACriticalControlOnlyAServerSendsIsRefusedAsUnavailable(Control $control): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                $control->setCriticality(true),
            );
            self::fail('The critical control should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }
    }

    /**
     * RFC 4511 4.1.11 holds a control the server does not take in a request to its criticality, whatever its value.
     *
     * @return iterable<string, array{Control}>
     */
    public static function controlsOnlyAServerSends(): iterable
    {
        yield 'a sort response with a malformed value' => [new Control(
            Control::OID_SORTING_RESPONSE,
            false,
            'garbage',
        )];
        yield 'a sync state' => [new SyncStateControl(
            SyncStateControl::STATE_ADD,
            str_repeat("\x11", 16),
        )];
    }
}
