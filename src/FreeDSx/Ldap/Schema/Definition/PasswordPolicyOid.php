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

namespace FreeDSx\Ldap\Schema\Definition;

/**
 * OIDs, names, and descriptions for draft-behera-ldap-password-policy-10 attributes and object classes.
 *
 * @api
 */
final class PasswordPolicyOid
{
    public const OID_PWD_ATTRIBUTE = '1.3.6.1.4.1.42.2.27.8.1.1';

    public const NAME_PWD_ATTRIBUTE = 'pwdAttribute';

    public const DESC_PWD_ATTRIBUTE = 'attribute to which the policy applies';

    public const OID_PWD_MIN_AGE = '1.3.6.1.4.1.42.2.27.8.1.2';

    public const NAME_PWD_MIN_AGE = 'pwdMinAge';

    public const DESC_PWD_MIN_AGE = 'minimum seconds between password changes';

    public const OID_PWD_MAX_AGE = '1.3.6.1.4.1.42.2.27.8.1.3';

    public const NAME_PWD_MAX_AGE = 'pwdMaxAge';

    public const DESC_PWD_MAX_AGE = 'maximum seconds a password remains valid';

    public const OID_PWD_IN_HISTORY = '1.3.6.1.4.1.42.2.27.8.1.4';

    public const NAME_PWD_IN_HISTORY = 'pwdInHistory';

    public const DESC_PWD_IN_HISTORY = 'number of prior passwords retained for history checks';

    public const OID_PWD_CHECK_QUALITY = '1.3.6.1.4.1.42.2.27.8.1.5';

    public const NAME_PWD_CHECK_QUALITY = 'pwdCheckQuality';

    public const DESC_PWD_CHECK_QUALITY = 'quality enforcement level (0=off, 1=lenient, 2=strict)';

    public const OID_PWD_MIN_LENGTH = '1.3.6.1.4.1.42.2.27.8.1.6';

    public const NAME_PWD_MIN_LENGTH = 'pwdMinLength';

    public const DESC_PWD_MIN_LENGTH = 'minimum password length in characters';

    public const OID_PWD_EXPIRE_WARNING = '1.3.6.1.4.1.42.2.27.8.1.7';

    public const NAME_PWD_EXPIRE_WARNING = 'pwdExpireWarning';

    public const DESC_PWD_EXPIRE_WARNING = 'seconds before expiration at which to warn the user';

    public const OID_PWD_GRACE_AUTHN_LIMIT = '1.3.6.1.4.1.42.2.27.8.1.8';

    public const NAME_PWD_GRACE_AUTHN_LIMIT = 'pwdGraceAuthNLimit';

    public const DESC_PWD_GRACE_AUTHN_LIMIT = 'number of grace logins permitted after expiration';

    public const OID_PWD_LOCKOUT = '1.3.6.1.4.1.42.2.27.8.1.9';

    public const NAME_PWD_LOCKOUT = 'pwdLockout';

    public const DESC_PWD_LOCKOUT = 'whether failed bind attempts can lock the account';

    public const OID_PWD_LOCKOUT_DURATION = '1.3.6.1.4.1.42.2.27.8.1.10';

    public const NAME_PWD_LOCKOUT_DURATION = 'pwdLockoutDuration';

    public const DESC_PWD_LOCKOUT_DURATION = 'seconds an account stays locked (0 = until reset)';

    public const OID_PWD_MAX_FAILURE = '1.3.6.1.4.1.42.2.27.8.1.11';

    public const NAME_PWD_MAX_FAILURE = 'pwdMaxFailure';

    public const DESC_PWD_MAX_FAILURE = 'failed bind threshold that triggers lockout';

    public const OID_PWD_FAILURE_COUNT_INTERVAL = '1.3.6.1.4.1.42.2.27.8.1.12';

    public const NAME_PWD_FAILURE_COUNT_INTERVAL = 'pwdFailureCountInterval';

    public const DESC_PWD_FAILURE_COUNT_INTERVAL = 'seconds before old failure counts are forgotten';

    public const OID_PWD_MUST_CHANGE = '1.3.6.1.4.1.42.2.27.8.1.13';

    public const NAME_PWD_MUST_CHANGE = 'pwdMustChange';

    public const DESC_PWD_MUST_CHANGE = 'whether the user must change password after admin reset';

    public const OID_PWD_ALLOW_USER_CHANGE = '1.3.6.1.4.1.42.2.27.8.1.14';

    public const NAME_PWD_ALLOW_USER_CHANGE = 'pwdAllowUserChange';

    public const DESC_PWD_ALLOW_USER_CHANGE = 'whether the user may change their own password';

    public const OID_PWD_SAFE_MODIFY = '1.3.6.1.4.1.42.2.27.8.1.15';

    public const NAME_PWD_SAFE_MODIFY = 'pwdSafeModify';

    public const DESC_PWD_SAFE_MODIFY = 'whether password change requires the existing password';

    public const OID_PWD_CHANGED_TIME = '1.3.6.1.4.1.42.2.27.8.1.16';

    public const NAME_PWD_CHANGED_TIME = 'pwdChangedTime';

    public const DESC_PWD_CHANGED_TIME = 'time the password was last changed';

    public const OID_PWD_ACCOUNT_LOCKED_TIME = '1.3.6.1.4.1.42.2.27.8.1.17';

    public const NAME_PWD_ACCOUNT_LOCKED_TIME = 'pwdAccountLockedTime';

    public const DESC_PWD_ACCOUNT_LOCKED_TIME = 'time the account became locked';

    public const OID_PWD_FAILURE_TIME = '1.3.6.1.4.1.42.2.27.8.1.19';

    public const NAME_PWD_FAILURE_TIME = 'pwdFailureTime';

    public const DESC_PWD_FAILURE_TIME = 'timestamps of recent consecutive bind failures';

    public const OID_PWD_HISTORY = '1.3.6.1.4.1.42.2.27.8.1.20';

    public const NAME_PWD_HISTORY = 'pwdHistory';

    public const DESC_PWD_HISTORY = 'history of prior password values';

    public const OID_PWD_GRACE_USE_TIME = '1.3.6.1.4.1.42.2.27.8.1.21';

    public const NAME_PWD_GRACE_USE_TIME = 'pwdGraceUseTime';

    public const DESC_PWD_GRACE_USE_TIME = 'timestamps of grace logins consumed after expiration';

    public const OID_PWD_RESET = '1.3.6.1.4.1.42.2.27.8.1.22';

    public const NAME_PWD_RESET = 'pwdReset';

    public const DESC_PWD_RESET = 'whether the password was reset and must be changed';

    public const OID_PWD_POLICY_SUBENTRY = '1.3.6.1.4.1.42.2.27.8.1.23';

    public const NAME_PWD_POLICY_SUBENTRY = 'pwdPolicySubentry';

    public const DESC_PWD_POLICY_SUBENTRY = 'DN of the pwdPolicy entry that governs this user';

    public const OID_PWD_MIN_DELAY = '1.3.6.1.4.1.42.2.27.8.1.24';

    public const NAME_PWD_MIN_DELAY = 'pwdMinDelay';

    public const DESC_PWD_MIN_DELAY = 'minimum seconds to delay after each failed bind';

    public const OID_PWD_MAX_DELAY = '1.3.6.1.4.1.42.2.27.8.1.25';

    public const NAME_PWD_MAX_DELAY = 'pwdMaxDelay';

    public const DESC_PWD_MAX_DELAY = 'maximum seconds to delay after each failed bind';

    public const OID_PWD_MAX_IDLE = '1.3.6.1.4.1.42.2.27.8.1.26';

    public const NAME_PWD_MAX_IDLE = 'pwdMaxIdle';

    public const DESC_PWD_MAX_IDLE = 'seconds without successful bind before lockout';

    public const OID_PWD_START_TIME = '1.3.6.1.4.1.42.2.27.8.1.27';

    public const NAME_PWD_START_TIME = 'pwdStartTime';

    public const DESC_PWD_START_TIME = 'time the password becomes valid for authentication';

    public const OID_PWD_END_TIME = '1.3.6.1.4.1.42.2.27.8.1.28';

    public const NAME_PWD_END_TIME = 'pwdEndTime';

    public const DESC_PWD_END_TIME = 'time the password stops being valid for authentication';

    public const OID_PWD_LAST_SUCCESS = '1.3.6.1.4.1.42.2.27.8.1.29';

    public const NAME_PWD_LAST_SUCCESS = 'pwdLastSuccess';

    public const DESC_PWD_LAST_SUCCESS = 'time of the last successful bind';

    public const OID_PWD_GRACE_EXPIRY = '1.3.6.1.4.1.42.2.27.8.1.30';

    public const NAME_PWD_GRACE_EXPIRY = 'pwdGraceExpiry';

    public const DESC_PWD_GRACE_EXPIRY = 'seconds after expiration during which grace logins remain valid';

    public const OID_PWD_MAX_LENGTH = '1.3.6.1.4.1.42.2.27.8.1.31';

    public const NAME_PWD_MAX_LENGTH = 'pwdMaxLength';

    public const DESC_PWD_MAX_LENGTH = 'maximum password length in characters';

    public const OID_PWD_POLICY = '1.3.6.1.4.1.42.2.27.8.2.1';

    public const NAME_PWD_POLICY = 'pwdPolicy';

    public const DESC_PWD_POLICY = 'auxiliary class for entries that define a password policy';

    /**
     * Sentinel for pwdAccountLockedTime indicating a permanent administrative lockout.
     */
    public const PERMANENT_LOCK_SENTINEL = '000001010000Z';

    private function __construct() {}
}
