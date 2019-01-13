DirSync
================

DirSync uses an Active Directory specific control to modify the behavior of a LDAP search to only return entries that
have changed. This can be useful for tracking changes against LDAP entries in certain circumstances. There are a few
requirements for a DirSync request:

* The account making the request must have the `DS-Replication-Get-Changes` extended right in AD.
* The search base must be a root naming context.
* The search scope must be Subtree.

Beyond that, the search can be any valid LDAP filter you want. There is an included helper class in this library for
performing a DirSync request more easily.

* [General Usage](#general-usage)
    * [The Paging Check Method](#the-paging-check-method)
    * [The Watch Method](#the-watch-method)
* [DirSync Class Methods](#dirsync-class-methods)
    * [hasChanges](#haschanges)
    * [getChanges](#getchanges)
    * [useCookie](#usecookie)
    * [getCookie](#getcookie)
    * [useNamingContext](#usenamingcontext)
    * [useFilter](#usefilter)
    * [useIncrementalValues](#useincrementalvalues)
    * [useObjectSecurity](#useobjectsecurity)
    * [useAncestorFirstOrder](#useancestorfirstorder)

# General Usage

To use the DirSync helper class you can instantiate it from the main LdapClient class using the `dirSync()` method:

```php
use FreeDSx\Ldap\Search\Filters;

# The most simple way to start DirSync:
#   * Guesses the root naming context from the rootDSE
#   * Uses the LDAP filter '(objectClass=*)'. Watches for changes in ALL entries in LDAP.
#   * Uses a default flag for incremental values. Only changes will be returned in the entries.
$dirSync = $client->dirSync();

# Can optionally pass a naming context / LDAP filter / attributes to watch as arguments.
# For example, watch only for user changes in the naming context "dc=example,dc=local":
$dirSync = $client->dirSync('dc=example,dc=local', Filters::equal('objectClass', 'user'));
```

There are two main methods for making use of the helper class listed below, depending on which better fits your needs.
There are also several methods available on the DirSync class for further customizing how it should work, which are also
defined further below.

## The Paging Check Method

The paging check method manually iterates through the changes in a loop:

```php
$dirSync = $ldap->dirSync();

# Store initial results of the sync here.
# The initial call to getChanges() returns all entries matching the LDAP filter.
$initialResults = null;

while (true) {
    # Check for any changes
    $entries = $dirSync->getChanges();
    # Keep going until we get all the changes from this query in one Entries collection
    while ($dirSync->hasChanges()) {
        # This merges the additional changes from the query into the original collection. 
        $entries->add(...$dirSync->getChanges());
    }
    # Store the results from the initial sync for references later if needed
    if ($initialResults === null) {
        $initialResults = $entries;
        var_dump('Initial sync: '.count($entries));
    # Do something with the changes...    
    } else {
        var_dump('Changes: '.count($entries));
    }
    # Wait 10 seconds before repeating the process to check for more changes...
    sleep(10);
}
```

## The Watch Method

The watch method makes use of an anonymous function and a polling interval (in seconds) to watch for and react to changes:

**Note**: The anonymous function is only called when the Entries object is **NOT** empty (ie. there are actually changes).

```php
use FreeDSx\Ldap\Entry\Entries;

# Optionally passes a polling interval of 60 seconds after the anonymous function...
$ldap->dirSync()->watch(function (Entries $entries, bool $isFirstSync) {
    # The first sync will always contain all entries that the filter matches...
    if ($isFirstSync) {
        var_dump('Initial sync: '.count($entries));
    # Subsequent syncs will only contain entries that have changed...    
    } else {
        var_dump('Changes: '.count($entries));
        foreach ($entries as $entry) {
            var_dump($entry->toArray());
        }
    }
}, 60);
```

# DirSync Class Methods

## hasChanges

The has changes method returns a boolean value indicating whether or not there are more changes to receive from the
current query. The DirSync query made by `getChanges()` works like paging, so you must call this method to determine
if you need to call `getChanges()` again to retrieve the rest of the entries. It should be used in the following
context:

```php
# Check for changes
$entries = $dirsync->getChanges();

# Keep going until there are no more changes left from the previous query
while ($dirsync->hasChanges()) {
    $entries->add(...$dirsync->getChanges());
}
```

## getChanges

This is the main method for checking LDAP for changes and returns an Entries collection object class. You should use the
above `hasChanges()` method after this to check if you need to call this again.

```php
# Check for changes
$entries = $dirsync->getChanges();

# Check how many entries were received
var_dump('Number of changes: '.count($entries));

# Iterate through the entries, checking the DN on each
foreach($entries as $entry) {
     var_dump($entry->getDn()->toString());
}
```

## useCookie

You can use the `useCookie()` method to explicitly set the cookie for the sync. The cookie is an opaque, binary value,
that is used to identify the sync. For instance, if you start the sync and want to later restart it, you could save the
cookie value somewhere then set it here with this method to restart the sync:

**Note**: This assumes that AD will still accept the cookie as valid. It may not depending on the circumstances.

```php
# Save the cookie off ...
$cookie = $dirsync->getCookie();

# ... 

# Set the cookie later to potentially resume the sync where you left off
# Continue with the getChanges() / hasChanges() like you normally would
dirsync->useCookie($cookie);
```
 
## getCookie

This method returns the current value of the cookie, which is an opaque, binary value, that is used to identify the
sync. It can be used in the context of the `useCookie()` method above.

## useNamingContext

This method can be passed a string value representing the root naming context to check for changes in. If this value is
null, then the helper by default will attempt to check for changes in the `defaultNamingContext` retrieved from the
rootDSE.

```php
# Explicitly set the naming context to check for changes in:
$dirsync->useNamingContext('dc=example,dc=local');
```

## useFilter

This method can be passed an object implementing the `FilterInterface`. This is the same filter that is constructed for
an LDAP search with the client. This filter is what limits the results for what is returned for the changes:

```php
use FreeDSx\Ldap\Search\Filters;

# Use the Filters factory helper to construct the LDAP filter to use.
# This filter would limit the results to just AD user objects.
$filter = Filters::and(
    Filters::equal('objectClass', 'user'),
    Filters::equal('objectClass', 'person')
);

$dirsync->useFilter($filter);
```

## useIncrementalValues

By default, this is set to true.

Accepts a boolean value to toggle this on or off. From [MS-ADTS](https://msdn.microsoft.com/en-us/library/cc223347.aspx):

> If this flag is not present, all of the values, up to a server-specified limit, in a multivalued attribute are returned
> when any value changes. If this flag is present, only the changed values are returned, provided the attribute is a 
> forward link value.

## useObjectSecurity

By default, this is not set.

Accepts a boolean value to toggle this on or off. From [MS-ADTS](https://msdn.microsoft.com/en-us/library/cc223347.aspx):

> If this flag is present, the client can only view objects and attributes that are otherwise accessible to the client.
> If this flag is not present, the server checks if the client has access rights to read the changes in the NC.

## useAncestorFirstOrder

By default, this is not set.

Accepts a boolean value to toggle this on or off. From [MS-ADTS](https://msdn.microsoft.com/en-us/library/cc223347.aspx):

> The server returns parent objects before child objects.
