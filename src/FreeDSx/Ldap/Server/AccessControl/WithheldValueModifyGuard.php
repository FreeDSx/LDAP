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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\Subject\MatchesBoundIdentity;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function in_array;

/**
 * Refuses a value-level add or delete that would confirm a value of an attribute the identity may not read.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WithheldValueModifyGuard
{
    use MatchesBoundIdentity;

    public function __construct(private WithheldAttributePolicy $policy) {}

    /**
     * A value assertion reveals through its result code whether the value is present, so it needs read of the attribute.
     *
     * A value assertion on the identity's own entry discloses nothing it does not already control.
     *
     * @throws OperationException
     */
    public function assertAllowed(
        ModifyRequest $request,
        TokenInterface $token,
    ): void {
        if ($this->isBoundIdentity($token, $request->getDn())) {
            return;
        }

        foreach ($request->getChanges() as $change) {
            if (!$this->isAddOrDelete($change)) {
                continue;
            }

            if ($this->policy->isWithheldFromFilter($change->getAttribute()->getName(), $token)) {
                throw new OperationException(
                    'Insufficient access rights.',
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                );
            }
        }
    }

    /**
     * An add or delete is answered from the stored values, so its result code reveals them; a replace is unconditional.
     */
    private function isAddOrDelete(Change $change): bool
    {
        return in_array(
            $change->getType(),
            [Change::TYPE_ADD, Change::TYPE_DELETE],
            true,
        );
    }
}
