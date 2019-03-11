Entries
==============

* [Creating Entries](#creating-entries)
    * [Using Arrays](#using-arrays)
    * [Using Entry Methods](#using-entry-methods)
* [Modifying Entries](#modifying-entries)
    * [Add Values](#add-values)
    * [Set Values](#set-values)
    * [Remove Values](#remove-values)
    * [Reset Values](#reset-values)
* [Renaming Entries](#renaming-entries)
* [Moving Entries](#moving-entries)
* [Entry Methods](#entry-methods)
    * [add](#add)
    * [remove](#remove)
    * [reset](#reset)
    * [set](#has)
    * [get](#get)
    * [has](#set)
    * [getAttributes](#getattributes)
    * [getDn](#getdn)
    * [changes](#changes)
    * [count](#count)
    * [toArray](#toarray)
    * [fromArray](#fromarray)
    
## Creating Entries

There are two easy methods for creating new LDAP entry objects. You can either construct it from a simple associative
array, or you can build up the entry using the methods used in modification. In both cases, you then send the entry to
LDAP using the `create()` method of the LdapClient.

### Using Arrays

```php
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;

# Create the entry with the LDAP client
# Use an associative array of values for the entry.
# Use a string as the DN.
try {
    $ldap->create(Entry::fromArray('cn=foo,dc=domain,dc=local', [
        'objectClass' => ['top', 'group'],
        'sAMAccountName' => 'foo',
    ]);
} catch (OperationException $e) {
    echo sprintf('Error adding entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;
}
```

### Using Entry Methods

```php
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;

# Construct an entry using a string DN.
$entry = new Entry('cn=foo,dc=domain,dc=local');
# Call any of the same values used in modification to build up the entry.
$entry->set('objectClass', 'top', 'group');
$entry->set('sAMAccountName', 'foo');

# Create the entry with the LDAP client
try {
    $ldap->create($entry);
} catch (OperationException $e) {
    echo sprintf('Error adding entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;
}
```

## Modifying Entries

The entry object has various methods built in for automatically creating changes to send back to LDAP in a more intuitive
object-oriented way. All changes are then sent to LDAP using the LdapClient `update()` method.

### Add Values

Add values to an attribute using the `add()` method. The method is variadic and expects the attribute name first, and any
number of values for the remaining parameters.

**Note**: This incrementally adds values to an attribute, it does not replace anything already existing.

```php
use FreeDSx\Ldap\Exception\OperationException;

# Search for an entry object to get its current attributes / values
$entry = $ldap->read('cn=foo,dc=domain,dc=local');

# Add a value to an attribute, checking if the attribute exists first.
if (!$entry->get('telephoneNumber')) {
    $entry->add('telephoneNumber', '555-5555');
}
# Add multiple values at once.
$entry->add('otherIpPhone', '12345', '67890', '55555');

# Send the built up changes back to LDAP to update the entry via the LDAP client update method.
try {
    $ldap->update($entry);
} catch (OperationException $e) {
    echo sprintf('Error modifying entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;;
}
```

### Set Values

Set values on an attribute using the `set()` method. The method is variadic and expects the attribute name first, and any
number of values for the remaining parameters.

**Note**: This replaces any values currently set (or not set) on the attribute.

```php
use FreeDSx\Ldap\Exception\OperationException;

# Search for an entry object to get its current attributes / values
$entry = $ldap->read('cn=foo,dc=domain,dc=local');

# Set a value for an attribute. This replaces any value it may, or may not, have.
$entry->set('description', 'Employee');
$entry->set('otherIpPhone', '12345', '67890', '55555');

# Send the built up changes back to LDAP to update the entry via the LDAP client update method.
try {
    $ldap->update($entry);
} catch (OperationException $e) {
    echo sprintf('Error modifying entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;;
}
```

**Note**: You can also set attributes via magic method property access against the entry object.

```php
if (!isset($enty->description)) {
    $entry->description = 'Employee';
}
$entry->otherIpPhone = ['12345', '67890'];
```

### Remove Values

Remove specific values on an attribute using the `remove()` method. The method is variadic and expects the attribute name
first, and any number of values for the remaining parameters.

**Note**: This removes specific values on the attribute. They must exist, otherwise an OperationException will be thrown.

```php
use FreeDSx\Ldap\Exception\OperationException;

# Search for an entry object to get its current attributes / values
$entry = $ldap->read('cn=foo,dc=domain,dc=local');

# We will use the returned attribute to check its values...
$telephoneNumbers = $entry->get('telephoneNumber');

# Remove a value only if it exists...
if ($telephoneNumbers && $telephoneNumbers->has('555-5555')) {
    $entry->remove('telephoneNumber', '555-5555');
}
$entry->remove('otherIpPhone', '12345', '67890', '55555');

# Send the built up changes back to LDAP to update the entry via the LDAP client update method.
try {
    $ldap->update($entry);
} catch (OperationException $e) {
    echo sprintf('Error modifying entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;;
}
```

### Reset Values

Reset values on an attribute using the `reset()` method. The method is variadic and expects the attribute name first,
and any number of additional attribute names for the remaining parameters.

**Note**: This resets all values on the attribute, leaving it completely empty. If the attribute already has no values 
then an OperationException will be thrown.

```php
use FreeDSx\Ldap\Exception\OperationException;

# Search for an entry object to get its current attributes / values
$entry = $ldap->read('cn=foo,dc=domain,dc=local');

# Remove any values an attribute may have
if ($entry->has('title')) {
    $entry->reset('title');
}
$entry->reset('otherIpPhone', 'otherPager'); 

# Send the built up changes back to LDAP to update the entry via the LDAP client update method.
try {
    $ldap->update($entry);
} catch (OperationException $e) {
    echo sprintf('Error modifying entry (%s): %s', $e->getCode(), $e->getMessage()).PHP_EOL;;
}
```

**Note**: You can also reset attributes via `unset()` against the entry object attributes.

```php
if (!isset($entry->description)) {
    unset($entry->description);
}
unset($entry-otherIpPhone);
```

## Renaming Entries

Renaming an entry changes its RDN, giving it a new DN in the process. This operation can be performed by using the
rename method of the LdapClient. It accepts the following arguments for the DN:

* An Entry object (such as the result of a search).
* A Dn object.
* A string DN.

The second argument (the new name / RDN) must be either:

* An RDN object.
* A string representing an RDN.

By default this operation removes the old name (RDN) associated with the entry.

```php
# Grab the entry object...
$entry = $client->read('cn=foo,dc=example,dc=com');

# Rename the entry obejct...
$client->rename($entry, 'cn=bar');

# Optionally rename without removing the old RDN...
$client->rename($entry, 'cn=foo', false);
```

## Moving Entries

Moving an entry changes the parent DN, giving it a new spot in the directory. It accepts the following arguments for
both the entry being moved and the new location / parent DN:

* An Entry object (such as the result of search).
* A Dn object.
* A string DN.

```php
# Grab the entry to move...
$entry = $client->read('cn=foo,dc=example,dc=com');

# Move the entry obejct to a new location...
$client->move($entry, 'ou=Terminated,dc=example,dc=com');
``` 
 
## Entry Methods

### add

Add values to an entry attribute. For more details, see the [modification section](#add-values). 

### remove

Remove specific values from an entry attribute. For more details, see the [modification section](#remove-values). 

### reset

Reset entry attribute(s). For more details, see the [modification section](#reset-values). 

### set

Set values to an entry attribute. For more details, see the [modification section](#set-values). 

### get

Get an attribute object by name. Optionally pass a boolean true to specify that options for the attribute
must also match. Returns an attribute object if it exists, otherwise it will return null.

```php
$phoneNumbers = $entry->get('otherIpPhone');

# The string representation of an attribute is a comma separated list of its values
echo "Numbers: ".$phoneNumbers.PHP_EOL;

# Iterate through the attribute values
foreach ($phoneNumbers as $number) {
    echo "Number: $number".PHP_EOL;
}

# The attribute is also countable. Returns the number of values
echo "Total Numbers: ".count($phoneNumbers).PHP_EOL;

# You can optionally check if the attribute has any options associated with it
if ($phoneNumbers->hasOptions()) {
    echo "Options: ".$phoneNumbers->getOptions().PHP_EOL;
}

# Check if a specific value exists in the attribute
if ($telephoneNumbers->has('55555')) {
    # do something...
}
```

### has

Check if an entry has a specific attribute. Optionally pass a boolean true to specify that options for the attribute
must also match.

```php
if ($enty->has('description')) {
    # do something...
}
```

**Note**: You can also use the magic `isset()` method against the entry object to check this.

```php
if (isset($enty->description)) {
    # do something...
}
```

### getAttributes

This returns the attributes of an entry as an array of Attribute objects.

```php
foreach ($entry->getAttributes() as $attribute) {
    echo sprintf('%s = %s', $attribute->getName(), $attribute).PHP_EOL;
}
```

**Note**: You can also accomplish the above by just looping over the entry, as it is iterable:

```php
foreach ($entry as $attribute) {
    echo sprintf('%s = %s', $attribute->getName(), $attribute).PHP_EOL;
}
```

### getDn

This returns the Dn object for the entry. 

```php
$dn = $entry->getDn();

# The string representation is just the string distinguished name
echo $dn.PHP_EOL;

# Get the immediate parent of the Dn (Returns null if none exists) 
echo 'Parent DN: '.$dn->getParent().PHP_EOL;

# Loop over the Dn to get each Rdn...
foreach($dn as $rdn) {
    echo "RDN: $rdn".PHP_EOL;
}

# Check how many RDNs the DN contains
echo 'Total RDNs: '.count($dn).PHP_EOL;

```

### changes

Each time you call one of the [modification methods](#modifying-entries) of the entry, a change object is created and
stored with the entry. It is cleared when the entry is either sent to LDAP via update or create.

This method returns the collection of changes, which itself is iterable / countable.

```php
$changes = $entry->changes();

foreach($changes as $change) {
    $attribute = $change->getAttribute();
    if ($change->isAdd()) {
        echo "Add: ".$attribute->getName().PHP_EOL;
    } elseif ($change->isDelete()) {
        echo "Delete: ".$attribute->getName().PHP_EOL;
    } elseif ($change->isReplace()) {
        echo "Replace: ".$attribute->getName().PHP_EOL;
    } elseif ($change->isReset()) {
        echo "Reset: ".$attribute->getName().PHP_EOL;
    }
}

# Check how many total changes there are
echo 'Total changes: '.count($changes).PHP_EOL;
``` 

### count

Returns the total number of attributes on the entry.

```php
echo "Total attributes: ".$entry->count().PHP_EOL;

# Also countable, so you can use count directly against the entry object
echo "Total attributes: ".count($entry).PHP_EOL;
``` 

### toArray

This method returns the entry as a PHP associative array with all the attribute names and values. Attribute values
are always in an array, regardless of how many there are.

```php
foreach($entry->toArray() as $attribute => $values) {
    echo sprintf('%s = %s', $attribute, implode(', ', $values)).PHP_EOL;
}
``` 

### fromArray

This static method is available for constructing an entry from an associative array of attributes and values. The first
parameter is the string DN for the entry, and the second parameter is the associative array of attributes and values.

**Note**: The values of the associative array can be either a string or an array of values. 

```php
use FreeDSx\Ldap\Entry\Entry;

$entry = Entry::fromArray('cn=foo,dc=domain,dc=local', [
    'objectClass' => ['top', 'group'],
    'sAMAccountName' => 'foo',
    'description' => 'Group of Users',
]);
```
