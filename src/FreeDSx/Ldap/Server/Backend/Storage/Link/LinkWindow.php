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

namespace FreeDSx\Ldap\Server\Backend\Storage\Link;

use FreeDSx\Ldap\Entry\Option;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;

use function ctype_digit;
use function min;
use function sprintf;

/**
 * One slice of a linked attribute.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkWindow
{
    /**
     * The high end a client writes for "however many are left".
     */
    private const TO_THE_END = '*';

    /**
     * @param int $first The first value's position, counting from zero.
     * @param ?int $last The last value's position, or null for however many are left.
     */
    private function __construct(
        public int $first = 0,
        public ?int $last = null,
    ) {}

    /**
     * The slice a range option asks for, or null when the option asks for something else.
     *
     * Nothing validates the option on the way in. The range is a non-standard option format.
     *
     * @throws OperationException when the range is malformed or ends before it starts
     */
    public static function fromOption(Option $option): ?self
    {
        if (!$option->isRange()) {
            return null;
        }
        $low = $option->getLowRange();
        $high = $option->getHighRange();

        if ($low === null || $high === null) {
            throw self::refuse($option);
        }
        // Naming no low end at all asks from the first value.
        $first = (int) $low;

        if ($high === self::TO_THE_END) {
            return new self($first);
        }
        if (!ctype_digit($high) || (int) $high < $first) {
            throw self::refuse($option);
        }

        return new self(
            $first,
            (int) $high,
        );
    }

    /**
     * The whole attribute, which is what a read that names no range asks for.
     */
    public static function whole(): self
    {
        return new self();
    }

    /**
     * Values to read for the slice, held to the cap.
     */
    public function size(int $cap): int
    {
        if ($this->last === null) {
            return $cap;
        }

        return min(
            $this->last - $this->first + 1,
            $cap,
        );
    }

    /**
     * Whether the slice starts where the attribute does, which is the only slice that can go unnamed.
     */
    public function startsAtFirst(): bool
    {
        return $this->first === 0;
    }

    /**
     * The name the values are returned under: ranged unless the whole attribute is there.
     *
     * @param int $count Values actually read for the slice.
     * @param bool $more Whether the attribute holds more past them.
     */
    public function nameFor(
        string $attribute,
        int $count,
        bool $more,
    ): string {
        if (!$more && $this->startsAtFirst()) {
            return $attribute;
        }

        return sprintf(
            '%s;range=%d-%s',
            $attribute,
            $this->first,
            $more
                ? (string) ($this->first + $count - 1)
                : self::TO_THE_END,
        );
    }

    private static function refuse(Option $option): OperationException
    {
        return new OperationException(
            sprintf('The range "%s" is not one this server can answer.', $option->toString()),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }
}
