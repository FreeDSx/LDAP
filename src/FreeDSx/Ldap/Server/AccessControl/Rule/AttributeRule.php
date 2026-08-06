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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\AccessControl\Target\AnyTargetMatcher;
use FreeDSx\Ldap\Server\AccessControl\Target\TargetMatcherInterface;

/**
 * An ordered access control rule gating an attribute's read (search filtering, Compare) and write (Add, Modify) access.
 *
 * An empty $attributes list matches all attributes.
 *
 * @api
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AttributeRule
{
    /**
     * @var string[]
     */
    public array $attributes;

    /**
     * @param string[] $attributes Attribute names, normalized here so a rule matches however it was spelled.
     */
    public function __construct(
        public Effect $effect,
        public SubjectMatcherInterface $subject,
        public TargetMatcherInterface $target,
        array $attributes,
        public AttributeAccess $access = AttributeAccess::Both,
    ) {
        $this->attributes = array_map(
            Attribute::normalizeName(...),
            $attributes,
        );
    }

    public static function allow(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$attributes,
    ): self {
        return new self(
            Effect::Allow,
            $subject,
            $target,
            $attributes,
        );
    }

    public static function deny(
        SubjectMatcherInterface $subject,
        TargetMatcherInterface $target = new AnyTargetMatcher(),
        string ...$attributes,
    ): self {
        return new self(
            Effect::Deny,
            $subject,
            $target,
            $attributes,
        );
    }

    /**
     * Narrow this rule to read access (search result filtering and Compare).
     */
    public function forRead(): self
    {
        return $this->withAccess(AttributeAccess::Read);
    }

    /**
     * Narrow this rule to write access (Add and Modify).
     */
    public function forWrite(): self
    {
        return $this->withAccess(AttributeAccess::Write);
    }

    private function withAccess(AttributeAccess $access): self
    {
        return new self(
            $this->effect,
            $this->subject,
            $this->target,
            $this->attributes,
            $access,
        );
    }
}
