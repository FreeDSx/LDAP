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
use FreeDSx\Ldap\Server\Utility\Memo\BoundedMemo;
use PHPUnit\Framework\TestCase;

use function str_repeat;

final class BoundedMemoTest extends TestCase
{
    /**
     * @var BoundedMemo<string, string>
     */
    private BoundedMemo $subject;

    /**
     * @var list<string>
     */
    private array $computed = [];

    protected function setUp(): void
    {
        $this->subject = new BoundedMemo(
            2,
            $this->answerFor(...),
        );
    }

    public function test_it_computes_an_answer_it_does_not_hold(): void
    {
        self::assertSame(
            'answer a',
            $this->subject->for('a'),
        );
        self::assertSame(
            ['a'],
            $this->computed,
        );
    }

    public function test_it_answers_a_remembered_key_without_computing_it_again(): void
    {
        $this->subject->for('a');

        self::assertSame(
            'answer a',
            $this->subject->for('a'),
        );
        self::assertSame(
            ['a'],
            $this->computed,
        );
    }

    public function test_it_empties_when_full_before_remembering_another_answer(): void
    {
        $this->subject->for('a');
        $this->subject->for('b');
        $this->subject->for('c');
        $this->subject->for('b');
        $this->subject->for('c');

        self::assertSame(
            ['a', 'b', 'c', 'b'],
            $this->computed,
        );
    }

    public function test_it_remembers_a_key_as_long_as_an_attribute_type(): void
    {
        $key = str_repeat(
            'k',
            Attribute::MAX_TYPE_LENGTH,
        );

        $this->subject->for($key);
        $this->subject->for($key);

        self::assertSame(
            [$key],
            $this->computed,
        );
    }

    public function test_it_answers_a_longer_key_without_remembering_it(): void
    {
        $key = str_repeat(
            'k',
            Attribute::MAX_TYPE_LENGTH + 1,
        );

        self::assertSame(
            'answer ' . $key,
            $this->subject->for($key),
        );
        $this->subject->for($key);

        self::assertSame(
            [$key, $key],
            $this->computed,
        );
    }

    public function test_it_remembers_a_numeric_key(): void
    {
        $this->subject->for('123');
        $this->subject->for('123');

        self::assertSame(
            ['123'],
            $this->computed,
        );
    }

    private function answerFor(string $key): string
    {
        $this->computed[] = $key;

        return 'answer ' . $key;
    }
}
