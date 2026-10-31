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

namespace Tests\Unit\FreeDSx\Ldap\Server\Utility\Memo;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Server\Utility\Memo\ArrayAccessMemo;
use PHPUnit\Framework\TestCase;

use function str_repeat;

final class ArrayAccessMemoTest extends TestCase
{
    /**
     * @var ArrayAccessMemo<string>
     */
    private ArrayAccessMemo $subject;

    protected function setUp(): void
    {
        $this->subject = new ArrayAccessMemo(2);
    }

    public function test_it_returns_the_answer_it_remembers(): void
    {
        self::assertSame(
            'x',
            $this->subject->remember(
                'a',
                'x',
            ),
        );
    }

    public function test_a_remembered_answer_is_read_from_its_answers(): void
    {
        $this->subject->remember(
            'a',
            'x',
        );

        self::assertSame(
            ['a' => 'x'],
            $this->subject->answers,
        );
    }

    public function test_it_empties_when_full_before_remembering_another_answer(): void
    {
        $this->subject->remember(
            'a',
            'x',
        );
        $this->subject->remember(
            'b',
            'y',
        );
        $this->subject->remember(
            'c',
            'z',
        );

        self::assertSame(
            ['c' => 'z'],
            $this->subject->answers,
        );
    }

    public function test_it_remembers_a_key_as_long_as_an_attribute_type(): void
    {
        $key = str_repeat(
            'k',
            Attribute::MAX_TYPE_LENGTH,
        );

        $this->subject->remember(
            $key,
            'x',
        );

        self::assertSame(
            [$key => 'x'],
            $this->subject->answers,
        );
    }

    public function test_it_returns_the_answer_for_a_longer_key_without_remembering_it(): void
    {
        self::assertSame(
            'x',
            $this->subject->remember(
                str_repeat(
                    'k',
                    Attribute::MAX_TYPE_LENGTH + 1,
                ),
                'x',
            ),
        );
        self::assertSame(
            [],
            $this->subject->answers,
        );
    }
}
