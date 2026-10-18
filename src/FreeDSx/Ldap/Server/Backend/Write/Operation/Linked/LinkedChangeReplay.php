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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation\Linked;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\LinkedValueLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;

use function array_diff_key;
use function array_values;
use function sprintf;

/**
 * Applies a modify's linked changes in request order to what the owner already links.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class LinkedChangeReplay
{
    public function __construct(
        private LinkedValueLookupInterface $lookup,
        private SchemaValidator $schema,
    ) {}

    /**
     * RFC 4511 4.6: each change applies to the state the ones before it left.
     *
     * @param list<Change> $changes
     *
     * @throws OperationException when a value is already linked, is not linked, or is not a DN
     */
    public function settle(
        array $changes,
        Dn $owner,
    ): LinkDelta {
        if ($changes === []) {
            return new LinkDelta();
        }
        $before = $this->heldBefore(
            $changes,
            $owner,
        );
        $state = $before;

        foreach ($changes as $change) {
            $name = Attribute::normalizeName($change->getAttribute()->getName());
            $values = array_values($change->getAttribute()->getValues());

            $state[$name] = $change->isAdd()
                ? $this->withAdded($name, $state[$name] ?? [], $values)
                : $this->withRemoved($name, $state[$name] ?? [], $values);
        }

        return $this->netOf(
            $before,
            $state,
        );
    }

    /**
     * What the owner links of every value the changes name.
     *
     * @param list<Change> $changes
     *
     * @return array<string, array<string, string>>
     */
    private function heldBefore(
        array $changes,
        Dn $owner,
    ): array {
        $named = [];

        foreach ($changes as $change) {
            $name = Attribute::normalizeName($change->getAttribute()->getName());

            foreach ($change->getAttribute()->getValues() as $value) {
                $named[$name][self::keyOf($value)] = $value;
            }
        }
        $held = [];

        foreach ($named as $name => $values) {
            foreach ($this->lookup->heldLinkValues($owner, $name, array_values($values)) as $value) {
                $held[$name][self::keyOf($value)] = $value;
            }
        }

        return $held;
    }

    /**
     * @param array<string, string> $current
     * @param list<string> $values
     *
     * @return array<string, string>
     *
     * @throws OperationException
     */
    private function withAdded(
        string $name,
        array $current,
        array $values,
    ): array {
        $adding = [];

        foreach ($values as $value) {
            $key = self::keyOf($value);

            if (isset($adding[$key])) {
                throw new OperationException(
                    sprintf('The attribute "%s" was given the same value twice.', $name),
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                );
            }
            if (isset($current[$key])) {
                throw new OperationException(
                    sprintf('The entry already holds a value given for the attribute "%s".', $name),
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                );
            }

            $adding[$key] = $value;
        }

        return $current + $adding;
    }

    /**
     * Every value is checked against the state before the change.
     *
     * @param array<string, string> $current
     * @param list<string> $values
     *
     * @return array<string, string>
     *
     * @throws OperationException
     */
    private function withRemoved(
        string $name,
        array $current,
        array $values,
    ): array {
        $removing = [];

        foreach ($values as $value) {
            $key = self::keyOf($value);

            if (!isset($current[$key])) {
                throw new OperationException(
                    sprintf('The entry does not hold a value given for the attribute "%s".', $name),
                    ResultCode::NO_SUCH_ATTRIBUTE,
                );
            }

            $removing[$key] = true;
        }

        return array_diff_key(
            $current,
            $removing,
        );
    }

    /**
     * Values the replay left changed, held to the syntax the whole entry would have been for the ones it adds.
     *
     * @param array<string, array<string, string>> $before
     * @param array<string, array<string, string>> $after
     *
     * @throws OperationException
     */
    private function netOf(
        array $before,
        array $after,
    ): LinkDelta {
        $added = [];
        $removed = [];

        foreach ($after as $name => $values) {
            $held = $before[$name] ?? [];
            $linking = array_values(array_diff_key($values, $held));
            $unlinking = array_values(array_diff_key($held, $values));

            if ($linking !== []) {
                $this->schema->validateValues(new Attribute($name, ...$linking));
                $added[$name] = $linking;
            }
            if ($unlinking !== []) {
                $removed[$name] = $unlinking;
            }
        }

        // Changes that cancel out leave the stored links as they are.
        return $added === [] && $removed === []
            ? LinkDelta::untouched()
            : new LinkDelta(
                $added,
                $removed,
            );
    }

    private static function keyOf(string $value): string
    {
        return Dn::normalizedOrNull($value) ?? $value;
    }
}
