Range Retrieval
==============

Range Retrieval is an Active Directory specific method for retrieving values from an attribute that has a large amount
of values associated with it. This is commonly used in the context of retrieving all members of an AD group which has
a large amount of members (ie. over 1500 or so members).

A helper class is provided by the LdapClient to make working with ranged attributes easier.

* [General Usage](#general-usage)
    * [Paging Ranged Values](#paging-ranged-values)
    * [Get All Ranged Values](#get-all-ranged-values)
* [RangeRetrieval Class Methods](#rangeretrieval-class-methods)
    * [hasMoreValues](#hasmorevalues)
    * [getMoreValues](#getmorevalues)
    * [getRanged](#getranged)
    * [getAllRanged](#getallranged)
    * [hasRanged](#hasranged)

# General Usage

To use the RangeRetrieval helper class you can instantiate it from the main LdapClient class using the `range()` method:

```php
# This range object is then used for iterating / checking for ranged attributes
$range = $client->range();
```

There are two main methods for making use of the helper class listed below, depending on which better fits your needs.
One is for paging through the values. Another is for retrieving all available values at once.

## Paging Ranged Values

You can page through the values in a ranged attribute by going through it in a loop:

```php
# Grab an entry with a ranged option attribute...
$entry = $client->read('CN=All Employees,DC=example,DC=local', ['member;range=0-*']);
$members = $entry->get('member');

# Store all values in an array, instantiate the range...
$allMembers = [];
$range = $ldap->range();

# Keep looping until has more values returns false...
while ($range()->hasMoreValues($members)) {
    # Grabs the next ranged member attribute with a new set of values
    $members = $range()->getMoreValues($entry, $members);
    $allMembers = array_merge($allMembers, $members->getValues());
}

echo 'Total members: '.count($allMembers).PHP_EOL;
```

## Get All Ranged Values

If you know the entry / DN and which attribute you want all the values for, you can get them with a single call:

```php
# Grabs all values from an attribute of an entry...
$members = $ldap->range()->getAllValues('CN=All Employees,DC=example,DC=local', 'member');

foreach($members as $member) {
    echo $member.PHP_EOL;
}
```

# RangeRetrieval Class Methods

## hasMoreValues

This method returns a boolean value indicating whether or not there are more values associated with the ranged attributed.
The RangeRetrieval query made by `getMoreValues()` works like paging, so you must call this method to determine if you 
need to call `getMoreValues()` again to retrieve more values for the attribute. It should be used in the following 
context:

```php
# Grab an entry with a ranged option attribute...
$entry = $client->read('CN=All Employees,DC=example,DC=local', ['member;range=0-*']);
$members = $entry->get('member');

# Store all values in an array, instantiate the range...
$allMembers = [];
$range = $ldap->range();

# Keep looping until hasMoreValues() returns false...
while ($range()->hasMoreValues($members)) {
    # Grabs the next ranged member attribute with a new set of values
    $members = $range()->getMoreValues($entry, $members);
    $allMembers = array_merge($allMembers, $members->getValues());
}

echo 'Total members: '.count($allMembers).PHP_EOL;
```

## getMoreValues

This method is used for retrieving the next set of values from a ranged attribute and would be used in the same context
described above in the `hasMoreValues()` method above.

**Note**: You can optionally pass a second parameter (integer) to this method to control how many values are retrieved at a time.

## hasRanged

You can use the `hasRanged()` method to determine if an entry contains any attributes that have a range option. It returns
a simple boolean value.

```php
# Read a single entry...
$entry = $client->read('CN=All Employees,DC=example,DC=local');

# Check if the entry has any ranged attributes...
if ($client->range()->hasRanged($entry)) {
    # Do something different with the ranged attributes...
}
```
 
## getRanged

Using this method you can retrieve a specific ranged attribute from an entry by using the attribute name. If the entry
has no ranged attribute with that name it will return null.

```php
# Read a single entry...
$entry = $client->read('CN=All Employees,DC=example,DC=local');

# Get the specific ranged member attribute
$member = $client->range()->getRanged($entry, 'member')

if ($member) {
    # Do something different with the ranged attribute...
}
```

## getAllRanged

This method returns all ranged attributes associated with an entry as an array of attribute objects.

```php
# Read a single entry...
$entry = $client->read('CN=All Employees,DC=example,DC=local');

# Get all the ranged attributes returned for an entry
$attributes = $client->range()->getAllRanged($entry)

foreach ($attributes as $attribute) {
    echo "Ranged Attribute: ".$attribute->getName().PHP_EOL;
}

echo "Total ranged attributes: ".count($attributes).PHP_EOL;
```

## getAllValues

This method can be used to easily retrieve all ranged values associated with an entry attribute. It only needs 2
parameters:

1. The entry. In the form: An entry object, a Dn object, or a string DN.
2. The attribute. In the form: An attribute object, or a string attribute name.

```php
# Grabs all values from an attribute of an entry...
$members = $ldap->range()->getAllValues('CN=All Employees,DC=example,DC=local', 'member');

foreach($members as $member) {
    echo $member.PHP_EOL;
}
echo "Total Values: ".count($members).PHP_EOL;
```
