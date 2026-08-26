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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Operation;

use Closure;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\ComputeUpdateHandler;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Backend\Write\WriteHandlerTestTrait;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class ComputeUpdateHandlerTest extends TestCase
{
    use WriteHandlerTestTrait;

    private const ALICE = 'cn=Alice,dc=example,dc=com';

    protected function setUp(): void
    {
        $this->writeGraph();
    }

    public function test_it_derives_changes_from_the_current_state(): void
    {
        $append = static fn(string $value): Closure => static fn(Entry $entry): array => [
            Change::replace(
                'pwdFailureTime',
                ...[
                    ...($entry->get('pwdFailureTime')?->getValues() ?? []),
                    $value,
                ],
            ),
        ];

        $this->compute(self::ALICE, $append('20260520120000Z'));
        $this->compute(self::ALICE, $append('20260520120500Z'));

        self::assertSame(
            ['20260520120000Z', '20260520120500Z'],
            array_values($this->find(self::ALICE)?->get('pwdFailureTime')?->getValues() ?? []),
        );
    }

    public function test_it_does_nothing_when_the_entry_is_absent(): void
    {
        $this->compute(
            'cn=Ghost,dc=example,dc=com',
            static fn(Entry $entry): array => [Change::replace('cn', 'ghost')],
        );

        self::assertNull($this->find('cn=Ghost,dc=example,dc=com'));
    }

    public function test_it_does_nothing_when_no_changes_are_computed(): void
    {
        $this->compute(
            self::ALICE,
            static fn(Entry $entry): array => [],
        );

        self::assertNull($this->find(self::ALICE)?->get('pwdFailureTime'));
    }

    public function test_it_stamps_the_modify_operational_attributes(): void
    {
        $this->compute(
            self::ALICE,
            static fn(Entry $entry): array => [Change::replace('pwdFailureTime', '20260520120000Z')],
        );

        $updated = $this->find(self::ALICE);
        self::assertNotNull($updated);
        self::assertNotNull($updated->get('modifyTimestamp'));
        self::assertNotNull($updated->get('modifiersName'));
    }

    /**
     * Validation is opted into by the tests that assert on it, rather than applied to every fixture here.
     */
    protected function makeServerOptions(): ServerOptions
    {
        return TestServerOptions::unvalidatedCore();
    }

    /**
     * @param Closure(Entry): list<Change> $compute
     */
    private function compute(
        string $dn,
        Closure $compute,
    ): void {
        $this->graph->get(ComputeUpdateHandler::class)->handle(
            new ComputeUpdateCommand(
                new Dn($dn),
                $compute,
            ),
            $this->systemContext(),
        );
    }
}
