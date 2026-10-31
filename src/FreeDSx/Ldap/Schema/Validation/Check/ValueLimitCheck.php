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

namespace FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Utility\Memo\BoundedMemo;

use function count;
use function sprintf;

/**
 * An attribute may hold no more values than its type's cap, or the server default when it declares none.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ValueLimitCheck implements SchemaCheckInterface
{
    private const MAX_REMEMBERED_TYPES = 1024;

    /**
     * Keyed on the base type, resolved on first use since the schema is fixed after startup.
     *
     * @var BoundedMemo<string, int>
     */
    private readonly BoundedMemo $valueLimits;

    public function __construct(
        private readonly Schema $schema,
        private readonly LinkedAttributes $linked,
        private readonly int $maxValues,
    ) {
        $this->valueLimits = new BoundedMemo(
            self::MAX_REMEMBERED_TYPES,
            $this->resolveValueLimit(...),
        );
    }

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        foreach ($write->entry->getAttributes() as $attribute) {
            // Values held apart from the entry cost one row each, so their count is not what this bounds.
            if ($this->linked->heldApart($attribute)) {
                continue;
            }
            $limit = $this->valueLimitFor($attribute);
            $count = count($attribute->getValues());

            if ($limit === AttributeType::EXTENSION_UNLIMITED_VALUES || $count <= $limit) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::ValueLimit,
                    ResultCode::ADMIN_LIMIT_EXCEEDED,
                    sprintf(
                        'Attribute "%s" holds %d values, which is beyond the limit of %d.',
                        $attribute->getName(),
                        $count,
                        $limit,
                    ),
                ),
            ];
        }

        return [];
    }

    /**
     * Keyed case-insensitively so every spelling of a type shares one entry.
     */
    private function valueLimitFor(Attribute $attribute): int
    {
        return $this->valueLimits->for(Attribute::normalizeName($attribute->getName()));
    }

    private function resolveValueLimit(string $type): int
    {
        return $this->schema->getAttributeType($type)?->maxValues() ?? $this->maxValues;
    }
}
