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

namespace Tests\Unit\FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Schema\Definition\PasswordPolicyOid;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use PHPUnit\Framework\TestCase;

final class RecordedOutcomeTest extends TestCase
{
    public function test_carries_both_outcome_and_changes(): void
    {
        $outcome = PasswordPolicyOutcome::allow();
        $changes = OperationalChanges::none();

        $recorded = new RecordedOutcome(
            $outcome,
            $changes,
        );

        self::assertSame(
            $outcome,
            $recorded->outcome,
        );
        self::assertSame(
            $changes,
            $recorded->changes,
        );
    }

    public function test_an_unstored_copy_keeps_the_decision_and_its_delay_but_none_of_its_changes(): void
    {
        $outcome = PasswordPolicyOutcome::allowWithGraceWarning(2);
        $recorded = new RecordedOutcome(
            $outcome,
            OperationalChanges::of(Change::replace(
                PasswordPolicyOid::NAME_PWD_GRACE_USE_TIME,
                '20260520120000Z',
            )),
            1.5,
        );

        $unstored = $recorded->unstored();

        self::assertSame(
            [
                $outcome,
                1.5,
                true,
                false,
            ],
            [
                $unstored->outcome,
                $unstored->delaySeconds,
                $unstored->changes->isEmpty(),
                $unstored->stored,
            ],
        );
    }
}
