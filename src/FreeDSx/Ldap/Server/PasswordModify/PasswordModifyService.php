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

namespace FreeDSx\Ldap\Server\PasswordModify;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PwdPolicyError;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\Backend\Auth\PasswordHashService;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteOperationDispatcher;
use FreeDSx\Ldap\Server\PasswordPolicy\Attempt\PasswordModifyAttempt;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\OperationalChanges;
use FreeDSx\Ldap\Server\PasswordPolicy\Decision\PasswordPolicyOutcome;
use FreeDSx\Ldap\Server\PasswordPolicy\Guard\PasswordPolicyChangeGuard;
use FreeDSx\Ldap\Server\PasswordPolicy\PasswordPolicyContext;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Performs the RFC 3062 password change.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PasswordModifyService
{
    public function __construct(
        private PasswordModifyTargetResolver $targetResolver,
        private AccessControlInterface $accessControl,
        private WriteOperationDispatcher $writeDispatcher,
        private PasswordHashService $hashService = new PasswordHashService(),
        private ?PasswordPolicyChangeGuard $changeGuard = null,
        private ?PasswordPolicyContext $passwordPolicyContext = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function change(
        PasswordModifyRequest $request,
        AuthenticatedTokenInterface $token,
        ControlBag $controls,
    ): PasswordModifyResult {
        $found = $this->targetResolver->find(
            $request,
            $token,
        );

        // Authorized ahead of reporting the absence, so a missing entry cannot be told from a forbidden one.
        $this->authorizeRequest(
            $token,
            $found?->getDn() ?? new Dn(''),
        );

        if ($found === null) {
            throw new OperationException(
                'The target entry does not exist.',
                ResultCode::NO_SUCH_OBJECT,
            );
        }

        $entry = $found;
        $targetDn = $entry->getDn();

        $this->verifyOldPassword(
            $request,
            $entry,
        );

        $newPassword = $request->getNewPassword();
        $generated = null;

        if ($newPassword === null) {
            $generated = $this->hashService->generate();
            $newPassword = $generated;
        }

        $isSelf = $this->isSelf(
            $token,
            $targetDn,
        );
        $this->assertSelfChangeWhenMustChange(
            $token,
            $isSelf,
        );
        $hashed = $this->hashService->hash($newPassword);
        $deltas = $this->changeGuard?->enforce(new PasswordModifyAttempt(
            target: $entry,
            newPassword: $newPassword,
            oldPassword: $request->getOldPassword(),
            isSelf: $isSelf,
            passwordIsCleartext: true,
        )) ?? OperationalChanges::none();

        $this->applyPasswordChange(
            $targetDn,
            $hashed,
            $deltas,
            $token,
            $controls,
        );

        // A successful self-change satisfies any pwdReset requirement, so lift the session restriction immediately.
        if ($isSelf) {
            $token->clearMustChangePassword();
        }

        return new PasswordModifyResult(
            $targetDn,
            $generated,
        );
    }

    private function isSelf(
        AuthenticatedTokenInterface $token,
        Dn $targetDn,
    ): bool {
        return $token->getResolvedDn()->normalize()->toString() === $targetDn->normalize()->toString();
    }

    /**
     * A pwdReset identity may only change its own password; an exop targeting another entry is refused
     * (draft-behera-10 §8.1.2).
     *
     * @throws OperationException
     */
    private function assertSelfChangeWhenMustChange(
        AuthenticatedTokenInterface $token,
        bool $isSelf,
    ): void {
        if ($isSelf || !$token->mustChangePassword()) {
            return;
        }

        $outcome = PasswordPolicyOutcome::deny(
            PwdPolicyError::CHANGE_AFTER_RESET,
            ResultCode::UNWILLING_TO_PERFORM,
            'The password must be changed before any other operation is permitted.',
        );
        $this->passwordPolicyContext?->setOutcome($outcome);

        throw new OperationException(
            $outcome->diagnostic,
            $outcome->ldapResultCode,
        );
    }

    /**
     * @throws OperationException
     */
    private function authorizeRequest(
        AuthenticatedTokenInterface $token,
        Dn $targetDn,
    ): void {
        $this->accessControl->authorizeOperation(
            OperationType::PasswordModify,
            $token,
            $targetDn,
        );
        $this->accessControl->authorizeAttribute(
            $token,
            $targetDn,
            'userPassword',
            AttributeAccess::Write,
        );
    }

    /**
     * @throws OperationException
     */
    private function verifyOldPassword(
        PasswordModifyRequest $request,
        Entry $entry,
    ): void {
        $oldPassword = $request->getOldPassword();

        if ($oldPassword === null) {
            return;
        }

        foreach ($entry->get('userPassword')?->getValues() ?? [] as $stored) {
            if ($this->hashService->verify($oldPassword, $stored)) {
                return;
            }
        }

        throw new OperationException(
            'Invalid credentials.',
            ResultCode::INVALID_CREDENTIALS,
        );
    }

    /**
     * Persists the new password plus any policy bookkeeping deltas in one command. When deltas are present the
     * command is system-flagged so the NO-USER-MODIFICATION operational attributes are accepted; ACL was already
     * checked in authorizeRequest().
     *
     * @throws OperationException
     */
    private function applyPasswordChange(
        Dn $targetDn,
        string $hashed,
        OperationalChanges $deltas,
        AuthenticatedTokenInterface $token,
        ControlBag $controls,
    ): void {
        $changes = [
            Change::replace('userPassword', $hashed),
            ...$deltas->changes,
        ];
        $context = $deltas->isEmpty()
            ? new WriteContext(
                $token,
                $controls,
            )
            : WriteContext::system(
                $token,
                $controls,
            );

        $this->writeDispatcher->dispatch(
            new UpdateCommand(
                $targetDn,
                $changes,
            ),
            $context,
        );
    }
}
