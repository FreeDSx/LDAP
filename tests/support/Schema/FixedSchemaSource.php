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

namespace Tests\Support\FreeDSx\Ldap\Schema;

use FreeDSx\Ldap\Schema\Definition\AttributeType;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaSourceInterface;

/**
 * Supplies definitions a test builds itself, for what no shipped resource declares.
 */
final class FixedSchemaSource implements SchemaSourceInterface
{
    private function __construct(private readonly Schema $schema) {}

    /**
     * References are resolved once the sources are merged, so these may build on a resource merged alongside them.
     */
    public static function withAttributeTypes(AttributeType ...$types): self
    {
        $schema = new Schema();

        foreach ($types as $type) {
            $schema->addAttributeType($type);
        }

        return new self($schema);
    }

    public function load(): Schema
    {
        return $this->schema;
    }
}
