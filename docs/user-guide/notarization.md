# Notarization

Notarization is the process initiated by an user (*the signer*), usually by running one of the following commands on an asset:

- `vcn notarize` to notarize the asset with [status](#Statuses) equals to **TRUSTED**
- `vcn untrust` to notarize the asset with [status](#Statuses) equals to **UNTRUSTED**
- `vcn unsupport` to notarize the asset with [status](#Statuses) equals to **UNSUPPORTED**

When process starts, a fingerprint (the digest or simply *the hash*) is derived from the block of digital data given as input (*the asset*) by using the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hashing function.

The hash (not the asset itself, that's never uploaded on nor shared with CodeNotary) alongside with the desired [status](#Statuses) is then cryptographically signed by using the the user's secret and stored on the [ZTC](https://zerotrustconsortium.org/) blockchain. There it remains forever and can never be changed, so it can later used to check the asset authenticity (e.g. invoking `vcn authenticate`).

In the end, the output of notarization process is a new blockchain entry with the hash bound to the following attributes:

Field | Label | Description 
------------ | ------------- | ------------- 
`Owner` | **Key** | The public address derived from the user's secret, also kwown as the signer's key.
`Level` | **Level** | The signer's [level](#Levels) at the time when the notarization was made.
`Status` | **Status** | The asset's [status](#Statuses) chosen by the signer at the time when the notarization was made.
`Timestamp` | **Date** | The date and time of the notarization.
> *Field*s are names used to map [the data stored onto the blockchain](https://github.com/vchain-us/vcn/blob/0.5.0/pkg/api/verify.go#L26), *Label*s are used by `vcn` when printing results.

## Authentication

Authentication is the process of verifying the asset's [status](#Statuses) on the blockchain, usually by running `vcn authenticate` against the asset.

Given an asset as input, the hash is computed in the same way the notarization process does. Then, the blochain entry matching the hash (*the authentication*) is retrieved and, if any, the result is returned otherwise a result with [status](#Statuses) equals to **UNKNOWN** is returned.

> By default, `vcn` tries to retrieve the last entry matching the current user (if logged in), if not found the last entry with highest [level](#Levels) is returned instead. Alternatively, it is also possible to retrive the authentication matching a specific signer (an user or an organization). 

## Statuses

Code | Status | Color | Description | Error message | Explanation
------------ | ------------- | ------------- | ------------ | ------------- | -------------
0 | **TRUSTED** | *green* | The asset was notarized. | *none* | The blockchain indicates that the asset is authentic and signer trusts it.
2 | **UNKNOWN** | *yellow* | The asset is not notarized. | *hash* was not notarized *[by <key/list of keys/org>]* | No notarization found on the blockchain for the asset.
1 | **UNTRUSTED** | *red* | The asset is untrusted. | *hash* is untrusted *[by <key/list of keys/org>]* | The  blockchain indicates that the signer DOES NOT trust the asset.
3 | **UNSUPPORTED** | *red* | The asset is unsupported. | *hash* is unsupported *[by <key/list of keys/org>]* | The blockchain indicates that the signer DOES NOT trust the asset because it is not supported anymore (eg. deprecated).

## Levels

Level | Label | Description 
------------ | ------------- | ------------- 
-1 | **DISABLED** | The signer's account is disabled.
0 | **UNKNOWN** | The signer's identity is unknown.
1 | **EMAIL_VERIFIED** | The signer's email is verified by CodeNotary platform.
2 | **SOCIAL_VERIFIED** | The signer's identity is verified by social media profiles.
3 | **ID_VERIFIED** | The signer provided an ID document.
4 | **LOCATION_VERIFIED** | The signer provided a proof-of-address.
99 | **VCHAIN** | *Reserved*
