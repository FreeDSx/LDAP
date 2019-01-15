Controls
================

This library contains lots of controls that help modify various aspects of a LDAP request. All of these controls can
be created from a helper class. You can also extend the the base Control class if you need to create your own custom
control. Some of these controls have helper classes designed to make using them easier.

* [Control Helper Methods](#control-helper-methods)
    * [create](#create)
    * [dirSync](#dirsync)
    * [expectedEntryCount](#expectedentrycount)
    * [extendedDn](#extendeddn)
    * [paging](#paging)
    * [policyHints](#policyhints)
    * [pwdPolicy](#pwdpolicy)
    * [sdFlags](#sdflags)
    * [setOwner](#setowner)
    * [showDeleted](#showdeleted)
    * [showRecycled](#showrecycled)
    * [sort](#sort)
    * [subtreeDelete](#subtreedelete)
    * [vlv](#vlv)
    * [vlvFilter](#vlvfilter)

# Control Helper Methods

All helper methods for creating controls can be called on the following class: `FreeDSx\Ldap\Controls`. You can then add
the controls to requests in two ways:

* Call the `controls()` method of the LdapClient and add / remove / update controls from that collection. Any controls
there will be sent with every request.
* Add the control as the last parameter to a method on the client, such as `read()`, `search()`, `create()`, `delete()`,
etc. This is variadic, so you can add as many controls as you want for that specific request.

```php
use FreeDSx\Ldap\Controls;

# Assuming $client is the LdapClient, globally add some controls:
$client->controls()->add(
    Controls::showDeleted(),
    Controls::policyHints() 
);

# Check if a control exists globally...
var_dump($client->controls()->has(Controls::showDeleted()));

# Remove a control that was globally added...
$client->controls()->remove(Controls::showDeleted());

# Get a control that was added globally
var_dump($client->controls()->get(Controls::policyHints()));

# Add a one time control individually to an outgoing request...
$client->delete('cn=foo,dc=example,dc=local', Controls::subtreeDelete());
```

## create

The create method is a way for generating arbitrary controls using the following parameters (in order):
 
 * A specific string OID
 * A boolean indicating the control criticality
 * An optional value, which can be an ASN.1 AbstractType object from the FreeDSx/ASN.1 library.

In its most simple form, pass it a string OID:

```php
use FreeDSx\Ldap\Controls;

# Create a control using a string OID:
$control = Controls::create('1.2.840.113556.1.4.805');
```

If you have a control that needs special ASN.1 structures in the value, you could construct that using the Asn1 helper
class from the `freedsx/asn1` library as well. In this example we will manually construct an AD Security Descriptor
control that needs an ASN.1 sequence with an integer value:

```php
use FreeDSx\Ldap\Controls;
use FreeDSx\Asn1\Asn1;

# Construct the needed ASN.1 structure:
$asn1 = Asn1::sequence(Asn1::integer(7));

# Construct the control, add the ASN.1 structure as the value (third argument)
# The second argument is a boolean that specifies whether or not the control is critical
# The value will get properly encoded when it is sent
$control = Controls::create('1.2.840.113556.1.4.801', true, $asn1);
```

## dirSync

Creates an AD DirSync control. See: https://msdn.microsoft.com/en-us/library/cc223347.aspx

It is not recommended to use the control directly, instead you should use the [DirSync helper class](DirSync.md)

## expectedEntryCount

Creates an AD Expected Entry Count control. See: https://msdn.microsoft.com/en-us/library/jj216720.aspx

This control can be used when searching LDAP to constrain the result set of entries to a specific min / max size. If
either of the constraints are violated then an OperationException is thrown.

```php
use FreeDSx\Ldap\Controls;

# The first paramter is the minimum allowed entries. Anything below this is not allowed.
# The second parameter is the maximum allowed entries. Anything above this is not allowed.
$control = Controls::expectedEntryCount(1, 100);
```

## extendedDn

Creates an AD Extended DN control. See: https://msdn.microsoft.com/en-us/library/cc223349.aspx

This control modifies how DNs are returned from LDAP on entries when searching. Instead of just return a string DN,
it will return a string containing the GUID and SID as well as the DN, in the form of:

`<GUID=bdbfd4b3-453c-42ee-98e2-7b4a698a61b8>;<SID=S-1-5-21-2354834273-1534127952-2340477679-500>;CN=Administrator, CN=Users,DC=Fabrikam,DC=com`

You can pass an optional boolean value for whether or not the SID / GUID should be represented as hexadecimal strings.

```php
use FreeDSx\Ldap\Controls;

# Construct an extended DN
$control = Controls::extendedDn();

# Construct an extended DN with hex encded values
$control = Controls::extendedDn(true);
```

## paging

Creates a paging control for search results.

It is not recommended to use the control directly, instead you should use the [Paging helper class](Searching-and-Filters.md#paging)

## policyHints

Creates an AD control indicating that password modifications to AD should adhere to password policy restrictions and
constraints. If you attempt to modify a password in AD with this control added, and it does not adhere to the restrictions,
then the operation will fail.

You can optionally pass a bool as to whether this should be true (default) or false.

## pwdPolicy

Creates a password policy control as specified in: https://tools.ietf.org/html/draft-behera-ldap-password-policy-10

When using this control, a password policy response control is returned from LDAP with the OID `1.3.6.1.4.1.42.2.27.8.5.1`.
The response contains additional details around why a password may have been rejected.

## sdFlags

Creates an AD control that specifies what specific parts of an `ntSecurityDescriptor` attribute should be received / modified,
depending on the context of the LDAP operation.

This control expects a flag integer as the only parameter. By default it creates a value that selects everything except
the SACL of the Security Descriptor. The possible flag values are documented here: https://msdn.microsoft.com/en-us/library/cc223323.aspx

```php
# Select / modify only the DACL
$control = Controls::sdFlags(4);
```

## setOwner

Creates an AD control to set the owner of an entry when performing an add entry against LDAP. To use this control you
must pass a string SID of the owner you want:

```php
# Create a control to pass to the `create()` method to set the owner for a newly created entry
$control = Controls::setOwner('S-1-5-32-544');
```

## showDeleted

Creates an AD control that returns deleted entries in a search result. This control has no additional parameters.

## showRecycled

Creates an AD control that returns recycled entries in a search result. This control has no additional parameters.

## sort

Creates a Server Side Sort control to help sort results received from a search.

For more information on this control, see the documentation under [sorting in the search docs](Searching-and-Filters.md#sorting) 

## subtreeDelete

Creates an AD control that, when used in the context of a deletion operation, deletes all children entries underneath the
entry being deleted (essentially a recursive deletion). This control has no additional parameters.

## vlv

Creates a VLV (Virtual List View) control for search results.

It is not recommended to use the control directly, instead you should use the [VLV helper class](Searching-and-Filters.md#vlv)

## vlvFilter

Creates a VLV (Virtual List View) control for search results.

It is not recommended to use the control directly, instead you should use the [VLV helper class](Searching-and-Filters.md#vlv)
