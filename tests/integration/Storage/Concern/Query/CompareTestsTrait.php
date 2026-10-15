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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;

/**
 * Compare, answered by the same matching rules a filter applies.
 */
trait CompareTestsTrait
{
    public function testCompareReturnsTrueForMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Smith',
        );

        self::assertTrue($result);
    }

    /**
     * RFC 4511 4.10: compareFalse means the values did not match, so an Undefined assertion needs its own code.
     */
    public function testCompareRefusesAnUnrecognizedAttributeType(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNDEFINED_ATTRIBUTE_TYPE);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'shoeSize',
            '9',
        );
    }

    public function testCompareRefusesAnAssertionValueTheSyntaxRejects(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::INVALID_ATTRIBUTE_SYNTAX);

        $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'uidNumber',
            'abc',
        );
    }

    /**
     * A defined type the entry lacks is False rather than Undefined, so it keeps answering compareFalse.
     */
    public function testCompareAnswersFalseWhenTheEntryLacksTheAttribute(): void
    {
        $this->authenticateUser();

        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'title',
            'anything',
        ));
    }

    public function testCompareAppliesTheSchemaDeclaredMatchingRule(): void
    {
        $this->authenticateUser();

        // labeledURI matches case exactly, so a case folded comparison must not be true.
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'labeledURI',
            'A1b2C3',
        ));
        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'labeledURI',
            'a1b2c3',
        ));
    }

    public function testCompareAgreesWithTheSameAssertionAsAFilter(): void
    {
        $this->authenticateUser();

        foreach (['A1b2C3', 'a1b2c3'] as $assertion) {
            $matched = $this->ldapClient()->search(
                Operations::search(Filters::equal('labeledURI', $assertion))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
            );

            self::assertSame(
                count($matched) === 1,
                $this->ldapClient()->compare(
                    'cn=alice,ou=people,dc=foo,dc=bar',
                    'labeledURI',
                    $assertion,
                ),
            );
        }
    }

    public function testCompareIsFalseWhenTheEntryLacksTheAttribute(): void
    {
        $this->authenticateUser();

        self::assertFalse($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'telephoneNumber',
            '555',
        ));
    }

    public function testCompareCoversValuesHeldBySubtypes(): void
    {
        $this->authenticateUser();

        // RFC 4512 2.5.2: cn is a subtype of name, so its value answers a comparison against the supertype.
        self::assertTrue($this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'name',
            'alice',
        ));
    }

    public function testCompareReturnsFalseForNonMatchingValue(): void
    {
        $this->authenticateUser();

        $result = $this->ldapClient()->compare(
            'cn=alice,ou=people,dc=foo,dc=bar',
            'sn',
            'Jones',
        );

        self::assertFalse($result);
    }
}
