<?php
/**
 * This file is part of the phpDS package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace PhpDs\Ldap;

use PhpDs\Ldap\Entry\Attribute;
use PhpDs\Ldap\Entry\Dn;
use PhpDs\Ldap\Entry\Entry;
use PhpDs\Ldap\Entry\Change;
use PhpDs\Ldap\Entry\Rdn;
use PhpDs\Ldap\Operation\Request\AbandonRequest;
use PhpDs\Ldap\Operation\Request\AddRequest;
use PhpDs\Ldap\Operation\Request\AnonBindRequest;
use PhpDs\Ldap\Operation\Request\CancelRequest;
use PhpDs\Ldap\Operation\Request\CompareRequest;
use PhpDs\Ldap\Operation\Request\DeleteRequest;
use PhpDs\Ldap\Operation\Request\ExtendedRequest;
use PhpDs\Ldap\Operation\Request\ModifyDnRequest;
use PhpDs\Ldap\Operation\Request\ModifyRequest;
use PhpDs\Ldap\Operation\Request\PasswordModifyRequest;
use PhpDs\Ldap\Operation\Request\SearchRequest;
use PhpDs\Ldap\Operation\Request\SimpleBindRequest;
use PhpDs\Ldap\Operation\Request\UnbindRequest;
use PhpDs\Ldap\Protocol\LdapMessage;
use PhpDs\Ldap\Search\Filter\EqualityFilter;
use PhpDs\Ldap\Search\Filter\FilterInterface;
use PhpDs\Ldap\Search\Filters;

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
     *
     * @param int|LdapMessage $messageId
     * @return CancelRequest
     */
    public static function cancel($messageId)
    {
        return new CancelRequest($messageId);
    }

    /**
     * @param string|Dn $dn
     * @param EqualityFilter $filter
     * @return CompareRequest
     */
    public static function compare($dn, EqualityFilter $filter)
    {
        return new CompareRequest($dn, $filter);
    }

    /**
     * Delete an entry from LDAP by its DN.
     *
     * @param string|Dn $dn
     * @return DeleteRequest
     */
    public static function delete($dn)
    {
        return new DeleteRequest($dn);
    }

    /**
     * Perform an extended operation.
     *
     * @param string $name
     * @param null|string $value
     * @return ExtendedRequest
     */
    public static function extended(string $name, ?string $value = null)
    {
        return new ExtendedRequest($name, $value);
    }

    /**
     * Perform modification(s) on an LDAP entry.
     *
     * @param string|Dn $dn
     * @param Change[] ...$changes
     * @return ModifyRequest
     */
    public static function modify(string $dn, Change ...$changes)
    {
        return new ModifyRequest($dn, ...$changes);
    }

    /**
     * Move an LDAP entry to a new parent DN location.
     *
     * @param string|Dn $dn
     * @param string|Dn $newParentDn
     * @return ModifyDnRequest
     */
    public static function move($dn, $newParentDn)
    {
        $dn = $dn instanceof Dn ? $dn : new Dn($dn);

        return new ModifyDnRequest($dn, $dn->getRdn(), true, $newParentDn);
    }

    /**
     * Creates a password modify extended operation.
     *
     * @param string $username
     * @param string $oldPassword
     * @param string $newPassword
     * @return PasswordModifyRequest
     */
    public static function passwordModify(string $username, string $oldPassword, string $newPassword)
    {
        return new PasswordModifyRequest($username, $oldPassword, $newPassword);
    }

    /**
     * Quit is an alias for unbind. This is more indicative of what an unbind actually does.
     *
     * @return UnbindRequest
     */
    public static function quit()
    {
        return self::unbind();
    }

    /**
     * Rename an LDAP entry by modifying its RDN.
     *
     * @param string|Dn $dn
     * @param string|Rdn $rdn
     * @param bool $deleteOldRdn
     * @return ModifyDnRequest
     */
    public static function rename($dn, $rdn, bool $deleteOldRdn = true)
    {
        return new ModifyDnRequest($dn, $rdn, $deleteOldRdn);
    }

    /**
     * Search LDAP with a given filter, scope, etc to retrieve a set of entries.
     *
     * @param FilterInterface $filter
     * @param array|Attribute $attributes
     * @return SearchRequest
     */
    public static function search(FilterInterface $filter, ...$attributes)
    {
        return new SearchRequest($filter, ...$attributes);
    }

    /**
     * Search for a specific base DN object to read. This sets a 'present' filter for the 'objectClass' attribute to help
     * simplify it.
     *
     * @param string|Dn $baseDn
     * @param array ...$attributes
     * @return SearchRequest
     */
    public static function searchRead($baseDn, ...$attributes)
    {
        return (new SearchRequest(Filters::present('objectClass'), ...$attributes))->base($baseDn)->useBaseScope();
    }

    /**
     * Search a single level list from a base DN object.
     *
     * @param FilterInterface $filter
     * @param string|Dn $baseDn
     * @param array ...$attributes
     * @return SearchRequest
     */
    public static function searchList(FilterInterface $filter, $baseDn, ...$attributes)
    {
        return (new SearchRequest($filter, ...$attributes))->base($baseDn)->useSingleLevelScope();
    }

    /**
     * A request to unbind. This actually causes the server to terminate the client connection.
     *
     * @return UnbindRequest
     */
    public static function unbind()
    {
        return new UnbindRequest();
    }

    /**
     * A request to determine who is currently authorized against LDAP for the current session.
     *
     * @return ExtendedRequest
     */
    public static function whoami()
    {
        return new ExtendedRequest(ExtendedRequest::OID_WHOAMI);
    }
}
