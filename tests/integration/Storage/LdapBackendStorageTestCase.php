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

namespace Tests\Integration\FreeDSx\Ldap\Storage;

use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\AssertionControlTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\BacklinkAttributeTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\BindTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\ControlValidationTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\DefaultAclTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\LinkedAttributeTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\AliasDereferencingTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\AttributeSelectionTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\CompareTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\FilterEvaluationTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\FilterMatchingTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\PagingControlTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\SearchLimitTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\SearchScopeTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query\SortControlTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\AttributeTypeSpellingTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\AttributeValueLimitTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\DnSpellingTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\ReadEntryControlTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\StorageBoundsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\SubtreeDeleteTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\SubtreeMoveTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\ValueMatchingWriteTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\WriteOperationTestsTrait;
use Tests\Integration\FreeDSx\Ldap\Storage\Concern\Write\WriteSchemaTestsTrait;

/**
 * Backend behavior shared by every storage adapter.
 *
 * Subclasses override storageExtraArgs() to route the shared server at a different backend, so the same cases run
 * against each one. Cases live in the Concern traits grouped by the behavior they cover.
 *
 * Abstract because only a subclass can pair an adapter with a runner it is sound on.
 */
abstract class LdapBackendStorageTestCase extends ServerTestCase
{
    use BindTestsTrait;
    use SearchScopeTestsTrait;
    use FilterEvaluationTestsTrait;
    use FilterMatchingTestsTrait;
    use AttributeSelectionTestsTrait;
    use CompareTestsTrait;
    use AliasDereferencingTestsTrait;
    use SearchLimitTestsTrait;
    use DefaultAclTestsTrait;
    use WriteOperationTestsTrait;
    use WriteSchemaTestsTrait;
    use ValueMatchingWriteTestsTrait;
    use DnSpellingTestsTrait;
    use AttributeTypeSpellingTestsTrait;
    use StorageBoundsTestsTrait;
    use AttributeValueLimitTestsTrait;
    use LinkedAttributeTestsTrait;
    use BacklinkAttributeTestsTrait;
    use SubtreeMoveTestsTrait;
    use SubtreeDeleteTestsTrait;
    use PagingControlTestsTrait;
    use SortControlTestsTrait;
    use ReadEntryControlTestsTrait;
    use AssertionControlTestsTrait;
    use ControlValidationTestsTrait;

    protected const SHARED_MAX_ATTRIBUTE_VALUES = 500;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-backend-storage',
            'tcp',
            static::storageExtraArgs(),
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-backend-storage');

        parent::setUp();
    }

    /**
     * Hook for subclasses to route the shared server through a different backend, spreading these to keep them.
     *
     * @return list<string>
     */
    protected static function storageExtraArgs(): array
    {
        return ['--max-attribute-values=' . self::SHARED_MAX_ATTRIBUTE_VALUES];
    }
}
