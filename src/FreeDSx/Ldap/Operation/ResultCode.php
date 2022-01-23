<?php

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Operation;

/**
 * Message response result codes. Defined in RFC 4511, 4.1.9
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ResultCode
{
    public const SUCCESS = 0;

    public const OPERATIONS_ERROR = 1;

    public const PROTOCOL_ERROR = 2;

    public const TIME_LIMIT_EXCEEDED = 3;

    public const SIZE_LIMIT_EXCEEDED = 4;

    public const COMPARE_FALSE = 5;

    public const COMPARE_TRUE = 6;

    public const AUTH_METHOD_UNSUPPORTED = 7;

    public const STRONGER_AUTH_REQUIRED = 8;

    public const REFERRAL = 10;

    public const ADMIN_LIMIT_EXCEEDED = 11;

    public const UNAVAILABLE_CRITICAL_EXTENSION = 12;

    public const CONFIDENTIALITY_REQUIRED = 13;

    public const SASL_BIND_IN_PROGRESS = 14;

    public const NO_SUCH_ATTRIBUTE = 16;

    public const UNDEFINED_ATTRIBUTE_TYPE = 17;

    public const INAPPROPRIATE_MATCHING = 18;

    public const CONSTRAINT_VIOLATION = 19;

    public const ATTRIBUTE_OR_VALUE_EXISTS = 20;

    public const INVALID_ATTRIBUTE_SYNTAX = 21;

    public const NO_SUCH_OBJECT = 32;

    public const ALIAS_PROBLEM = 33;

    public const INVALID_DN_SYNTAX = 34;

    public const ALIAS_DEREFERENCING_PROBLEM = 36;

    public const INAPPROPRIATE_AUTHENTICATION = 48;

    public const INVALID_CREDENTIALS = 49;

    public const INSUFFICIENT_ACCESS_RIGHTS = 50;

    public const BUSY = 51;

    public const UNAVAILABLE = 52;

    public const UNWILLING_TO_PERFORM = 53;

    public const LOOP_DETECT = 54;

    public const NAMING_VIOLATION = 64;

    public const OBJECT_CLASS_VIOLATION = 65;

    public const NOT_ALLOWED_ON_NON_LEAF = 66;

    public const NOT_ALLOWED_ON_RDN = 67;

    public const ENTRY_ALREADY_EXISTS = 68;

    public const OBJECT_CLASS_MODS_PROHIBITED = 69;

    public const AFFECTS_MULTIPLE_DSAS = 71;

    public const VIRTUAL_LIST_VIEW_ERROR = 76;

    public const OTHER = 80;

    public const CANCELED = 118;

    public const NO_SUCH_OPERATION = 119;

    public const TOO_LATE = 120;

    public const CANNOT_CANCEL = 121;

    public const ASSERTION_FAILED = 122;

    public const AUTHORIZATION_DENIED = 123;

    public const SYNCHRONIZATION_REFRESH_REQUIRED = 4096;

    public const MEANING_SHORT = [
        self::SUCCESS => 'success',
        self::OPERATIONS_ERROR => 'operationsError',
        self::PROTOCOL_ERROR => 'protocolError',
        self::TIME_LIMIT_EXCEEDED => 'timeLimitExceeded',
        self::SIZE_LIMIT_EXCEEDED => 'sizeLimitExceeded',
        self::COMPARE_FALSE => 'compareFalse',
        self::COMPARE_TRUE => 'compareTrue',
        self::AUTH_METHOD_UNSUPPORTED => 'authMethodNotSupported',
        self::STRONGER_AUTH_REQUIRED => 'strongerAuthRequired',
        self::REFERRAL => 'referral',
        self::ADMIN_LIMIT_EXCEEDED => 'adminLimitExceeded',
        self::UNAVAILABLE_CRITICAL_EXTENSION => 'unavailableCriticalExtension',
        self::CONFIDENTIALITY_REQUIRED => 'confidentialityRequired',
        self::SASL_BIND_IN_PROGRESS => 'saslBindInProgress',
        self::NO_SUCH_ATTRIBUTE => 'noSuchAttribute',
        self::UNDEFINED_ATTRIBUTE_TYPE => 'undefinedAttributeType',
        self::INAPPROPRIATE_MATCHING => 'inappropriateMatching',
        self::CONSTRAINT_VIOLATION => 'constraintViolation',
        self::ATTRIBUTE_OR_VALUE_EXISTS => 'attributeOrValueExists',
        self::INVALID_ATTRIBUTE_SYNTAX => 'invalidAttributeSyntax',
        self::NO_SUCH_OBJECT => 'noSuchObject',
        self::ALIAS_PROBLEM => 'aliasProblem',
        self::INVALID_DN_SYNTAX => 'invalidDNSyntax',
        self::ALIAS_DEREFERENCING_PROBLEM => 'aliasDereferencingProblem',
        self::INAPPROPRIATE_AUTHENTICATION => 'inappropriateAuthentication',
        self::INVALID_CREDENTIALS => 'invalidCredentials',
        self::INSUFFICIENT_ACCESS_RIGHTS => 'insufficientAccessRights',
        self::BUSY => 'busy',
        self::UNAVAILABLE => 'unavailable',
        self::UNWILLING_TO_PERFORM => 'unwillingToPerform',
        self::LOOP_DETECT => 'loopDetect',
        self::NAMING_VIOLATION => 'namingViolation',
        self::OBJECT_CLASS_VIOLATION => 'objectClassViolation',
        self::NOT_ALLOWED_ON_NON_LEAF => 'notAllowedOnNonLeaf',
        self::NOT_ALLOWED_ON_RDN => 'notAllowedOnRDN',
        self::ENTRY_ALREADY_EXISTS => 'entryAlreadyExists',
        self::OBJECT_CLASS_MODS_PROHIBITED => 'objectClassModsProhibited',
        self::AFFECTS_MULTIPLE_DSAS => 'affectsMultipleDSAs',
        self::OTHER => 'other',
        self::VIRTUAL_LIST_VIEW_ERROR => 'virtualListViewError',
        self::CANNOT_CANCEL => 'cannotCancel',
        self::TOO_LATE => 'tooLate',
        self::NO_SUCH_OPERATION => 'noSuchOperation',
        self::AUTHORIZATION_DENIED => 'authorizationDenied',
    ];

    public const MEANING_DESCRIPTION = [
        self::SUCCESS => 'Indicates the successful completion of an operation.',
        self::OPERATIONS_ERROR => 'Indicates that the operation is not properly sequenced with relation to other operations (of same or different type).',
        self::PROTOCOL_ERROR => 'Indicates the server received data that is not well-formed.',
        self::TIME_LIMIT_EXCEEDED => 'Indicates that the time limit specified by the client was exceeded before the operation could be completed.',
        self::SIZE_LIMIT_EXCEEDED => 'Indicates that the size limit specified by the client was exceeded before the operation could be completed.',
        self::COMPARE_FALSE => 'Indicates that the Compare operation has successfully completed and the assertion has evaluated to FALSE or Undefined.',
        self::COMPARE_TRUE => 'Indicates that the Compare operation has successfully completed and the assertion has evaluated to TRUE.',
        self::AUTH_METHOD_UNSUPPORTED => 'Indicates that the authentication method or mechanism is not supported.',
        self::STRONGER_AUTH_REQUIRED => 'Indicates the server requires strong(er) authentication in order to complete the operation.',
        self::REFERRAL => 'Indicates that a referral needs to be chased to complete the operation.',
        self::ADMIN_LIMIT_EXCEEDED => 'Indicates that an administrative limit has been exceeded.',
        self::UNAVAILABLE_CRITICAL_EXTENSION => 'Indicates a critical control is unrecognized.',
        self::CONFIDENTIALITY_REQUIRED => 'Indicates that data confidentiality protections are required.',
        self::SASL_BIND_IN_PROGRESS => 'Indicates the server requires the client to send a new bind request, with the same SASL mechanism, to continue the authentication process.',
        self::NO_SUCH_ATTRIBUTE => 'Indicates that the named entry does not contain the specified attribute or attribute value.',
        self::UNDEFINED_ATTRIBUTE_TYPE => 'Indicates that a request field contains an unrecognized attribute description.',
        self::INAPPROPRIATE_MATCHING => 'Indicates that an attempt was made (e.g., in an assertion) to use a matching rule not defined for the attribute type concerned.',
        self::CONSTRAINT_VIOLATION => 'Indicates that the client supplied an attribute value that does not conform to the constraints placed upon it by the data model.',
        self::ATTRIBUTE_OR_VALUE_EXISTS => 'Indicates that the client supplied an attribute or value to be added to an entry, but the attribute or value already exists.',
        self::INVALID_ATTRIBUTE_SYNTAX => 'Indicates that a purported attribute value does not conform to the syntax of the attribute.',
        self::NO_SUCH_OBJECT => 'Indicates that the object does not exist in the DIT.',
        self::ALIAS_PROBLEM => 'Indicates that an alias problem has occurred.  For example, the code may used to indicate an alias has been dereferenced that names no object.',
        self::INVALID_DN_SYNTAX => 'Indicates that an LDAPDN or RelativeLDAPDN field (e.g., search base, target entry, ModifyDN newrdn, etc.) of a request does not conform to the required syntax or contains attribute values that do not conform to the syntax of the attribute\'s type.',
        self::ALIAS_DEREFERENCING_PROBLEM => 'Indicates that a problem occurred while dereferencing an alias.  Typically, an alias was encountered in a situation where it was not allowed or where access was denied.',
        self::INAPPROPRIATE_AUTHENTICATION => 'Indicates the server requires the client that had attempted to bind anonymously or without supplying credentials to provide some form of credentials.',
        self::INVALID_CREDENTIALS => 'Indicates that the provided credentials (e.g., the user\'s name and password) are invalid.',
        self::INSUFFICIENT_ACCESS_RIGHTS => 'Indicates that the client does not have sufficient access rights to perform the operation.',
        self::BUSY => 'Indicates that the server is too busy to service the operation.',
        self::UNAVAILABLE => 'Indicates that the server is shutting down or a subsystem necessary to complete the operation is offline.',
        self::UNWILLING_TO_PERFORM => 'Indicates that the server is unwilling to perform the operation.',
        self::LOOP_DETECT => 'Indicates that the server has detected an internal loop (e.g., while dereferencing aliases or chaining an operation).',
        self::NAMING_VIOLATION => 'Indicates that the entry\'s name violates naming restrictions.',
        self::OBJECT_CLASS_VIOLATION => ' Indicates that the entry violates object class restrictions.',
        self::NOT_ALLOWED_ON_NON_LEAF => 'Indicates that the operation is inappropriately acting upon a non-leaf entry.',
        self::NOT_ALLOWED_ON_RDN => 'Indicates that the operation is inappropriately attempting to remove a value that forms the entry\'s relative distinguished name.',
        self::ENTRY_ALREADY_EXISTS => 'Indicates that the request cannot be fulfilled (added, moved, or renamed) as the target entry already exists.',
        self::OBJECT_CLASS_MODS_PROHIBITED => 'Indicates that an attempt to modify the object class(es) of an entry\'s \'objectClass\' attribute is prohibited.',
        self::AFFECTS_MULTIPLE_DSAS => 'Indicates that the operation cannot be performed as it would affect multiple servers (DSAs).',
        self::OTHER => 'Indicates the server has encountered an internal error.',
        self::VIRTUAL_LIST_VIEW_ERROR => 'This error indicates that the search operation failed due to the inclusion of the VirtualListViewRequest control.',
        self::CANNOT_CANCEL => 'The cannotCancel resultCode is returned if the identified operation does not support cancelation or the cancel operation could not be performed.',
        self::TOO_LATE => 'Indicates that it is too late to cancel the outstanding operation.',
        self::NO_SUCH_OPERATION => 'The server has no knowledge of the operation requested for cancelation.',
    ];
}
