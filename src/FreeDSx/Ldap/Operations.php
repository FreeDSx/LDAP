<?php
/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap;

use FreeDSx\Asn1\Type\AbstractType;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\CompareRequest;
use FreeDSx\Ldap\Operation\Request\DeleteRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\PasswordModifyRequest;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Protocol\ProtocolElementInterface;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

/**
 * Provides a set of factory methods to help quickly construct different operations/requests.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class Operations
{
    /**
     * A request to abandon an ongoing operation.
     *
     * @param int $id
     * @return AbandonRequest
     */
    public static function abandon(int $id)
    {
        return new AbandonRequest($id);
    }

    /**
     * Add an entry to LDAP.
     *
     * @param Entry $entry
     * @return AddRequest
     */
    public static function add(Entry $entry)
    {
        return new AddRequest($entry);
    }

    /**
     * A simple bind request with a username and password.
     *
     * @param string $username
     * @param string $password
     * @return SimpleBindRequest
     */
    public static function bind(string $username, string $password)
    {
        return new SimpleBindRequest($username, $password);
    }

    /**
     * A SASL bind request with a specific mechanism and their associated options.
     *
     * @param array $options
     * @param string $mechanism
     * @param string|null $credentials
     * @return SaslBindRequest
     */
    public static function bindSasl(array $options = [], string $mechanism = '', ?string $credentials = null)
    {
        return new SaslBindRequest($mechanism, $credentials, $options);
    }

    /**
     * An anonymous bind request.
     *
     * @param string $username
     * @return AnonBindRequest
     */
    public static function bindAnonymously(string $username = '')
    {
        return new AnonBindRequest($username);
    }

    /**
     * Cancel a specific operation. Pass either the message ID or the LdapMessage object.
     */
    public static function cancel(int $messageId): CancelRequest
    {
        return new CancelRequest($messageId);
    }

    /**
     * A comparison operation to check if an entry has an attribute with a certain value.
     *
     * @return CompareRequest
     */
    public static function compare(string $dn, string $attributeName, string $value): CompareRequest
    {
        return new CompareRequest($dn, Filters::equal($attributeName, $value));
    }

    /**
     * Delete an entry from LDAP by its DN.
     */
    public static function delete(string $dn): DeleteRequest
    {
        return new DeleteRequest($dn);
    }

    /**
     * Perform an extended operation.
     *
     * @param null|AbstractType|ProtocolElementInterface|string $value
     */
    public static function extended(string $name, $value = null): ExtendedRequest
    {
        return new ExtendedRequest($name, $value);
    }

    /**
     * Perform modification(s) on an LDAP entry.
     */
    public static function modify(string $dn, Change ...$changes): ModifyRequest
    {
        return new ModifyRequest($dn, ...$changes);
    }

    /**
     * Move an LDAP entry to a new parent DN location.
     */
    public static function move(string $dn, string $newParentDn): ModifyDnRequest
    {
        $dnObj = new Dn($dn);

        return new ModifyDnRequest($dn, $dnObj->getRdn()->toString(), true, $newParentDn);
    }

    /**
     * Creates a password modify extended operation.
     */
    public static function passwordModify(string $username, string $oldPassword, string $newPassword): PasswordModifyRequest
    {
        return new PasswordModifyRequest($username, $oldPassword, $newPassword);
    }

    /**
     * Quit is an alias for unbind. This is more indicative of what an unbind actually does.
     */
    public static function quit(): UnbindRequest
    {
        return self::unbind();
    }

    /**
     * Rename an LDAP entry by modifying its RDN.
     *
     * @param string|Rdn $rdn
     */
    public static function rename(string $dn, $rdn, bool $deleteOldRdn = true): ModifyDnRequest
    {
        return new ModifyDnRequest($dn, $rdn, $deleteOldRdn);
    }

    /**
     * Search LDAP with a given filter, scope, etc to retrieve a set of entries.
     *
     * @param string[]|Attribute[] ...$attributes
     */
    public static function search(FilterInterface $filter, ...$attributes): SearchRequest
    {
        return new SearchRequest($filter, ...$attributes);
    }

    /**
     * Search for a specific base DN object to read. This sets a 'present' filter for the 'objectClass' attribute to help
     * simplify it.
     *
     * @param array ...$attributes
     */
    public static function read(string $baseDn, ...$attributes): SearchRequest
    {
        return (new SearchRequest(Filters::present('objectClass'), ...$attributes))->base($baseDn)->useBaseScope();
    }

    /**
     * Search a single level list from a base DN object.
     *
     * @param array ...$attributes
     */
    public static function list(FilterInterface $filter, string $baseDn, ...$attributes): SearchRequest
    {
        return (new SearchRequest($filter, ...$attributes))->base($baseDn)->useSingleLevelScope();
    }

    /**
     * A request to unbind. This actually causes the server to terminate the client connection.
     *
     * @return UnbindRequest
     */
    public static function unbind(): UnbindRequest
    {
        return new UnbindRequest();
    }

    /**
     * A request to determine who is currently authorized against LDAP for the current session.
     *
     * @return ExtendedRequest
     */
    public static function whoami(): ExtendedRequest
    {
        return new ExtendedRequest(ExtendedRequest::OID_WHOAMI);
    }
}
