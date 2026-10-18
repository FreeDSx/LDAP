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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Pdo;

use FreeDSx\Ldap\Container;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Server\Backend\Storage\Import\LdapImporter;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Operation\UpdateEntryHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\AnonToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Server\Configuration\TestServerOptions;

final class ValidatedUpdateEntryHandlerTest extends TestCase
{
    private const BASE = 'o=example';

    private const BOB = 'cn=Bob,o=example';

    private UpdateEntryHandler $subject;

    protected function setUp(): void
    {
        $container = Container::forServer(TestServerOptions::validatedSqlite(
            SchemaValidationMode::Strict,
            SchemaResource::Core,
            SchemaResource::PasswordPolicy,
        ));
        $this->subject = $container->get(UpdateEntryHandler::class);

        $container->get(LdapImporter::class)->importEntries([
            Entry::fromArray(
                self::BASE,
                [
                    'objectClass' => ['organization'],
                    'o' => ['example'],
                ],
            ),
            Entry::fromArray(
                self::BOB,
                [
                    'objectClass' => ['person'],
                    'cn' => ['Bob'],
                    'sn' => ['Bob'],
                ],
            ),
        ]);
    }

    public function test_a_system_write_adding_a_second_password_policy_pointer_is_refused(): void
    {
        $this->systemModify(Change::add(
            'pwdPolicySubentry',
            self::BASE,
        ));

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::CONSTRAINT_VIOLATION);

        $this->systemModify(Change::add(
            'pwdPolicySubentry',
            self::BOB,
        ));
    }

    private function systemModify(Change ...$changes): void
    {
        $this->subject->handle(
            new UpdateCommand(
                new Dn(self::BOB),
                $changes,
            ),
            WriteContext::system(
                new AnonToken(),
                new ControlBag(),
            ),
        );
    }
}
