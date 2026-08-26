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

namespace FreeDSx\Ldap\Server\PasswordPolicy\Guard\BindStrategy;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordBindAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\RecordedOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyEngine;
use FreeDSx\Ldap\Server\PasswordPolicy\UserPasswordState;
use FreeDSx\Ldap\Server\Token\SystemToken;

/**
 * Evaluates and records every bind against the authoritative entry state (the primary / writable server).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryBindStrategy implements PasswordPolicyBindStrategyInterface
{
    public function __construct(
        private PasswordPolicyEngine $engine,
        private WriteHandlerInterface $writes,
    ) {}

    public function preBindOutcome(PasswordBindAttempt $attempt): PasswordPolicyOutcome
    {
        return $this->engine->evaluatePreBind(
            $attempt->state,
            $attempt->policy,
        );
    }

    public function record(
        PasswordBindAttempt $attempt,
        callable $decide,
    ): RecordedOutcome {
        $recorded = null;

        $this->writes->handle(
            new ComputeUpdateCommand(
                $attempt->dn,
                function (Entry $entry) use ($decide, &$recorded): array {
                    $recorded = $decide(UserPasswordState::fromEntry($entry));

                    return $recorded->changes->changes;
                },
            ),
            WriteContext::system(
                new SystemToken(),
                new ControlBag(),
            ),
        );

        return $recorded ?? new RecordedOutcome(
            PasswordPolicyOutcome::allow(),
            OperationalChanges::none(),
        );
    }
}
