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
 * OIDs, names, aliases, and descriptions for standard LDAP attribute types (RFC 4519 + RFC 4512 operational).
 *
 * @api
 */
final class AttributeTypeOid
{
    public const OID_OBJECT_CLASS = '2.5.4.0';

    public const NAME_OBJECT_CLASS = 'objectClass';

    public const DESC_OBJECT_CLASS = 'object classes of the entity';

    public const OID_ALIASED_OBJECT_NAME = '2.5.4.1';

    public const NAME_ALIASED_OBJECT_NAME = 'aliasedObjectName';

    public const ALIAS_ALIASED_OBJECT_NAME = 'aliasedEntryName';

    public const DESC_ALIASED_OBJECT_NAME = 'name of aliased object';

    public const OID_NAME = '2.5.4.41';

    public const NAME_NAME = 'name';

    public const DESC_NAME = 'common supertype of name attributes';

    public const OID_CN = '2.5.4.3';

    public const NAME_CN = 'cn';

    public const ALIAS_CN = 'commonName';

    public const DESC_CN = 'common name(s) of the object';

    public const OID_SN = '2.5.4.4';

    public const NAME_SN = 'sn';

    public const ALIAS_SN = 'surname';

    public const DESC_SN = 'last (family) name(s) for which the entity is known';

    public const OID_GIVEN_NAME = '2.5.4.42';

    public const NAME_GIVEN_NAME = 'givenName';

    public const DESC_GIVEN_NAME = 'first name(s) for which the entity is known';

    public const OID_INITIALS = '2.5.4.43';

    public const NAME_INITIALS = 'initials';

    public const DESC_INITIALS = 'initials of some or all of the names';

    public const OID_C = '2.5.4.6';

    public const NAME_C = 'c';

    public const ALIAS_C = 'countryName';

    public const DESC_C = 'two-letter ISO 3166 country code';

    public const OID_L = '2.5.4.7';

    public const NAME_L = 'l';

    public const ALIAS_L = 'localityName';

    public const DESC_L = 'locality in which the entity resides';

    public const OID_ST = '2.5.4.8';

    public const NAME_ST = 'st';

    public const ALIAS_ST = 'stateOrProvinceName';

    public const DESC_ST = 'state or province in which the entity resides';

    public const OID_STREET = '2.5.4.9';

    public const NAME_STREET = 'street';

    public const ALIAS_STREET = 'streetAddress';

    public const DESC_STREET = 'site for the local distribution of postal addresses';

    public const OID_O = '2.5.4.10';

    public const NAME_O = 'o';

    public const ALIAS_O = 'organizationName';

    public const DESC_O = 'organization(s) to which the entity belongs';

    public const OID_OU = '2.5.4.11';

    public const NAME_OU = 'ou';

    public const ALIAS_OU = 'organizationalUnitName';

    public const DESC_OU = 'organizational units of which the entity is a member';

    public const OID_TITLE = '2.5.4.12';

    public const NAME_TITLE = 'title';

    public const DESC_TITLE = 'title(s) held by the entity';

    public const OID_DESCRIPTION = '2.5.4.13';

    public const NAME_DESCRIPTION = 'description';

    public const DESC_DESCRIPTION = 'descriptive information';

    public const OID_POSTAL_CODE = '2.5.4.17';

    public const NAME_POSTAL_CODE = 'postalCode';

    public const DESC_POSTAL_CODE = 'codes used by a postal service';

    public const OID_TELEPHONE_NUMBER = '2.5.4.20';

    public const NAME_TELEPHONE_NUMBER = 'telephoneNumber';

    public const DESC_TELEPHONE_NUMBER = 'telephone numbers';

    public const OID_MEMBER = '2.5.4.31';

    public const NAME_MEMBER = 'member';

    public const DESC_MEMBER = 'distinguished names of objects on a list or in a group';

    public const OID_SEE_ALSO = '2.5.4.34';

    public const NAME_SEE_ALSO = 'seeAlso';

    public const DESC_SEE_ALSO = 'distinguished name(s) of objects related to the entity';

    public const OID_USER_PASSWORD = '2.5.4.35';

    public const NAME_USER_PASSWORD = 'userPassword';

    public const DESC_USER_PASSWORD = 'passwords used to authenticate the entity';

    public const OID_UNIQUE_MEMBER = '2.5.4.50';

    public const NAME_UNIQUE_MEMBER = 'uniqueMember';

    public const DESC_UNIQUE_MEMBER = 'distinguished names with optional unique identifiers';

    public const OID_UID = '0.9.2342.19200300.100.1.1';

    public const NAME_UID = 'uid';

    public const ALIAS_UID = 'userid';

    public const DESC_UID = 'user identifiers';

    public const OID_MAIL = '0.9.2342.19200300.100.1.3';

    public const NAME_MAIL = 'mail';

    public const ALIAS_MAIL = 'rfc822Mailbox';

    public const DESC_MAIL = 'electronic mail addresses';

    public const OID_DC = '0.9.2342.19200300.100.1.25';

    public const NAME_DC = 'dc';

    public const ALIAS_DC = 'domainComponent';

    public const DESC_DC = 'DNS label of the domain component';

    public const OID_JPEG_PHOTO = '0.9.2342.19200300.100.1.60';

    public const NAME_JPEG_PHOTO = 'jpegPhoto';

    public const DESC_JPEG_PHOTO = 'JPEG images';

    public const OID_DISPLAY_NAME = '2.16.840.1.113730.3.1.241';

    public const NAME_DISPLAY_NAME = 'displayName';

    public const DESC_DISPLAY_NAME = 'preferred name for display';

    public const OID_EMPLOYEE_NUMBER = '2.16.840.1.113730.3.1.3';

    public const NAME_EMPLOYEE_NUMBER = 'employeeNumber';

    public const DESC_EMPLOYEE_NUMBER = 'numerically identifies an employee within an organization';

    public const OID_MEMBER_OF = '1.2.840.113556.1.2.102';

    public const NAME_MEMBER_OF = 'memberOf';

    public const DESC_MEMBER_OF = 'distinguished names of groups the entity is a member of';

    public const OID_LABELED_URI = '1.3.6.1.4.1.250.1.57';

    public const NAME_LABELED_URI = 'labeledURI';

    public const DESC_LABELED_URI = 'URIs with optional labels';

    public const OID_CREATE_TIMESTAMP = '2.5.18.1';

    public const NAME_CREATE_TIMESTAMP = 'createTimestamp';

    public const DESC_CREATE_TIMESTAMP = 'time at which the object was created';

    public const OID_MODIFY_TIMESTAMP = '2.5.18.2';

    public const NAME_MODIFY_TIMESTAMP = 'modifyTimestamp';

    public const DESC_MODIFY_TIMESTAMP = 'time at which the object was last modified';

    public const OID_CREATORS_NAME = '2.5.18.3';

    public const NAME_CREATORS_NAME = 'creatorsName';

    public const DESC_CREATORS_NAME = 'name of the creator of the object';

    public const OID_MODIFIERS_NAME = '2.5.18.4';

    public const NAME_MODIFIERS_NAME = 'modifiersName';

    public const DESC_MODIFIERS_NAME = 'name of the last modifier of the object';

    public const OID_ADMINISTRATIVE_ROLE = '2.5.18.5';

    public const NAME_ADMINISTRATIVE_ROLE = 'administrativeRole';

    public const DESC_ADMINISTRATIVE_ROLE = 'administrative roles the entry is an administrative point for';

    public const OID_SUBTREE_SPECIFICATION = '2.5.18.6';

    public const NAME_SUBTREE_SPECIFICATION = 'subtreeSpecification';

    public const DESC_SUBTREE_SPECIFICATION = 'the portion of a subtree a subentry applies to';

    public const OID_SUBSCHEMA_SUBENTRY = '2.5.18.10';

    public const NAME_SUBSCHEMA_SUBENTRY = 'subschemaSubentry';

    public const DESC_SUBSCHEMA_SUBENTRY = 'DN of the subschema entry governing the entity';

    public const OID_HAS_SUBORDINATES = '2.5.18.9';

    public const NAME_HAS_SUBORDINATES = 'hasSubordinates';

    public const DESC_HAS_SUBORDINATES = 'whether the entry has any subordinate entries';

    public const OID_STRUCTURAL_OBJECT_CLASS = '2.5.21.9';

    public const NAME_STRUCTURAL_OBJECT_CLASS = 'structuralObjectClass';

    public const DESC_STRUCTURAL_OBJECT_CLASS = 'structural object class of the entry';

    public const OID_ENTRY_UUID = '1.3.6.1.1.16.4';

    public const NAME_ENTRY_UUID = 'entryUUID';

    public const DESC_ENTRY_UUID = 'universally unique identifier for the entry';

    public const OID_ENTRY_DN = '1.3.6.1.1.20';

    public const NAME_ENTRY_DN = 'entryDN';

    public const DESC_ENTRY_DN = 'DN of the entry';

    // RFC 4512 subschema attributes

    public const OID_ATTRIBUTE_TYPES = '2.5.21.5';

    public const NAME_ATTRIBUTE_TYPES = 'attributeTypes';

    public const DESC_ATTRIBUTE_TYPES = 'attribute type descriptions';

    public const OID_OBJECT_CLASSES = '2.5.21.6';

    public const NAME_OBJECT_CLASSES = 'objectClasses';

    public const DESC_OBJECT_CLASSES = 'object class descriptions';

    public const OID_MATCHING_RULES = '2.5.21.4';

    public const NAME_MATCHING_RULES = 'matchingRules';

    public const DESC_MATCHING_RULES = 'matching rule descriptions';

    public const OID_MATCHING_RULE_USE = '2.5.21.8';

    public const NAME_MATCHING_RULE_USE = 'matchingRuleUse';

    public const DESC_MATCHING_RULE_USE = 'matching rule use descriptions';

    public const OID_LDAP_SYNTAXES = '1.3.6.1.4.1.1466.101.120.16';

    public const NAME_LDAP_SYNTAXES = 'ldapSyntaxes';

    public const DESC_LDAP_SYNTAXES = 'LDAP syntax descriptions';

    public const OID_DIT_STRUCTURE_RULES = '2.5.21.1';

    public const NAME_DIT_STRUCTURE_RULES = 'dITStructureRules';

    public const DESC_DIT_STRUCTURE_RULES = 'DIT structure rules';

    public const OID_DIT_CONTENT_RULES = '2.5.21.2';

    public const NAME_DIT_CONTENT_RULES = 'dITContentRules';

    public const DESC_DIT_CONTENT_RULES = 'DIT content rules';

    public const OID_NAME_FORMS = '2.5.21.7';

    public const NAME_NAME_FORMS = 'nameForms';

    public const DESC_NAME_FORMS = 'name forms';

    private function __construct() {}
}
