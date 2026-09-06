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

namespace FreeDSx\Ldap\Server\AccessControl\Rule;

use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;

/**
 * An ordered access control rule gating whether an attribute may be named in a search filter.
 *
 * Separate from a read deny, which strips the value but leaves the attribute usable in a filter.
 *
 * Carries no target since a filter is answered before a search runs.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FilterAccessRule
{
    use TargetlessSubjectTrait;

    /**
     * @param string[] $attributes Attribute names. Empty matches every attribute.
     */
    private function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public array $attributes,
    ) {
        self::assertSubjectNeedsNoTarget($subject);
    }

    public static function allow(
        SubjectMatcherInterface $subject,
        string ...$attributes,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $attributes,
        );
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        string ...$attributes,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $attributes,
        );
    }
}
