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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Replica;

use DateTimeImmutable;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\GeneralizedTime;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;

/**
 * Replica-owned volatile password-policy attributes for one subject, held locally.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReplicaPasswordState
{
    /**
     * @var array<string, Attribute> keyed by lowercased attribute name
     */
    private array $attributes;

    /**
     * @param list<Attribute> $attributes
     */
    public function __construct(array $attributes = [])
    {
        $keyed = [];

        foreach ($attributes as $attribute) {
            $keyed[strtolower($attribute->getName())] = $attribute;
        }

        $this->attributes = $keyed;
    }

    public static function empty(): self
    {
        return new self();
    }

    /**
     * @param array<string, list<string>> $values
     */
    public static function fromArray(array $values): self
    {
        $attributes = [];
        foreach ($values as $name => $vals) {
            $attributes[] = Attribute::fromArray(
                $name,
                $vals,
            );
        }

        return new self($attributes);
    }

    public function isEmpty(): bool
    {
        return $this->attributes === [];
    }

    public function equals(self $other): bool
    {
        return $this->toArray() == $other->toArray();
    }

    /**
     * @return array<string, list<string>>
     */
    public function toArray(): array
    {
        $values = [];
        foreach ($this->attributes as $attribute) {
            $values[$attribute->getName()] = array_values($attribute->getValues());
        }

        return $values;
    }

    /**
     * Apply engine-emitted operational deltas (replace / reset) and return the resulting state.
     */
    public function withChanges(OperationalChanges $changes): self
    {
        $attributes = $this->attributes;

        foreach ($changes->changes as $change) {
            $attribute = $change->getAttribute();
            $key = strtolower($attribute->getName());

            if ($change->isReset() || $attribute->getValues() === []) {
                unset($attributes[$key]);

                continue;
            }

            $attributes[$key] = $attribute;
        }

        return new self(array_values($attributes));
    }

    /**
     * Project this local state onto a partial entry so the shared UserPasswordState parser can read it.
     */
    public function toUserPasswordState(Dn $dn): UserPasswordState
    {
        return UserPasswordState::fromEntry(Entry::raw(
            $dn,
            array_values($this->attributes),
        ));
    }

    /**
     * The password this state was recorded against, as the entry's pwdChangedTime then, or null when it had none.
     */
    public function version(): ?DateTimeImmutable
    {
        return $this->toUserPasswordState(new Dn(''))->changedAt;
    }

    public function isRecordedAgainst(?DateTimeImmutable $version): bool
    {
        return UserPasswordState::isSameVersion(
            $this->version(),
            $version,
        );
    }

    /**
     * Whether this state was recorded against a password set after $version, an absent version being the oldest.
     */
    public function isNewerThan(?DateTimeImmutable $version): bool
    {
        $recorded = $this->version();

        return $recorded !== null
            && ($version === null || $recorded > $version);
    }

    public function withVersion(?DateTimeImmutable $version): self
    {
        $attributes = $this->attributes;
        unset($attributes[strtolower(PasswordPolicyOid::NAME_PWD_CHANGED_TIME)]);

        if ($version !== null) {
            $attributes[] = new Attribute(
                PasswordPolicyOid::NAME_PWD_CHANGED_TIME,
                GeneralizedTime::formatWithFraction($version),
            );
        }

        return new self(array_values($attributes));
    }
}
