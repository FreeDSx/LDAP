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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\AccessControl\Subject\SubjectMatcherInterface;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Token\PrivilegedTokenInterface;

use function array_diff;
use function array_push;
use function array_values;
use function count;
use function sprintf;

/**
 * Refuses userPassword values a bind could not verify within the limits, or that the writer may not supply.
 *
 * Note: Every value is verified on a failed bind, so how many an entry holds bounds what one bind can cost.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class StoredPasswordGuard
{
    public function __construct(
        private PasswordHashService $hashService,
        private int $maxValues = 1,
        private bool $allowPreHashed = false,
        private ?SubjectMatcherInterface $administrators = null,
    ) {}

    /**
     * The userPassword values an entry holds, under any options.
     *
     * @return list<string>
     */
    public function valuesOf(Entry $entry): array
    {
        $password = new Attribute(AttributeTypeOid::NAME_USER_PASSWORD);
        $values = [];

        foreach ($entry->getAttributes() as $attribute) {
            if ($attribute->equals($password)) {
                array_push(
                    $values,
                    ...array_values($attribute->getValues()),
                );
            }
        }

        return $values;
    }

    /**
     * @param list<string> $heldBefore The values the entry held before the write, which it may keep as they are.
     *
     * @throws OperationException
     */
    public function assertStorable(
        Entry $entry,
        array $heldBefore,
        WriteContext $context,
    ): void {
        $values = $this->valuesOf($entry);

        if (count($values) > $this->maxValues) {
            throw new OperationException(
                sprintf(
                    'The attribute "%s" holds more values than the %d allowed.',
                    AttributeTypeOid::NAME_USER_PASSWORD,
                    $this->maxValues,
                ),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }

        foreach (array_diff($values, $heldBefore) as $value) {
            $this->assertSupplied(
                $value,
                $entry->getDn(),
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function assertSupplied(
        string $value,
        Dn $dn,
        WriteContext $context,
    ): void {
        if (!$this->hashService->isHashed($value)) {
            return;
        }
        if (!$this->hashService->isWithinLimits($value)) {
            throw new OperationException(
                sprintf(
                    'A pre-hashed "%s" value asks for more work than the configured hash limits allow.',
                    AttributeTypeOid::NAME_USER_PASSWORD,
                ),
                ResultCode::CONSTRAINT_VIOLATION,
            );
        }
        if ($this->allowPreHashed || $this->isAdministrator($context, $dn)) {
            return;
        }

        throw new OperationException(
            sprintf(
                'A pre-hashed "%s" value is accepted from administrators only.',
                AttributeTypeOid::NAME_USER_PASSWORD,
            ),
            ResultCode::CONSTRAINT_VIOLATION,
        );
    }

    /**
     * The server's own writes, the manager, and the configured administrators.
     */
    private function isAdministrator(
        WriteContext $context,
        Dn $dn,
    ): bool {
        $token = $context->getToken();

        return $context->isSystem()
            || $token instanceof PrivilegedTokenInterface
            || $this->administrators?->matches($token, $dn) === true;
    }
}
