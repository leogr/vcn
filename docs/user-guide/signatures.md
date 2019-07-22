# Signatures

A signature is made by the user by using a key (*the signer*), usually by running one of the following commands on an asset:

- `vcn sign` to sign the asset with [status](#Statuses) equals to **TRUSTED**
- `vcn untrust` to sign the asset with [status](#Statuses) equals to **UNTRUSTED**
- `vcn unsupport` to sign the asset with [status](#Statuses) equals to **UNSUPPORTED**

When the signature process starts, a fingerprint (the digest or simply *the hash*) is derived from the block of digital data given as input (*the asset*) by using the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hashing function.

The hash (not the asset's data itself) alongside with the desired [status](#Statuses) is then signed by using the signer's key (*the signature*) and stored on the [ZTC](https://zerotrustconsortium.org/) blockchain. There it remains forever and can never be changed, so it can later used for verification purpose.

In the end, when the hash is stored the following attributes are bound:

Field | Label | Description 
------------ | ------------- | ------------- 
`Owner` | **Key** | The signer's wallet address, also kwown as the signer's key.
`Level` | **Level** | The signer's [level](#Levels) at the time when the signature was made.
`Status` | **Status** | The asset's [status](#Statuses) chosen by the signer at the time when the signature was made.
`Timestamp` | **Date** | The date and time of the signature.
> *Field*s are names used to map [the data stored onto the blockchain](https://github.com/vchain-us/vcn/blob/0.5.0/pkg/api/verify.go#L26), *Label*s are used by `vcn` when printing results.

## Statuses

Code | Status | Color | Description | Error message | Explanation
------------ | ------------- | ------------- | ------------ | ------------- | -------------
0 | **TRUSTED** | *green* | The asset was signed. | *none* | The signature on the blockchain indicates that the signer trusts that asset.
2 | **UNKNOWN** | *yellow* | The asset was not signed. | *hash* was not signed *[by <key/list of keys/org>]* | There's no signature on the blockchain.
1 | **UNTRUSTED** | *red* | The asset is untrusted. | *hash* was is untrusted *[by <key/list of keys/org>]* | The signature on the blockchain indicates that the signer DOES NOT trust that asset.
3 | **UNSUPPORTED** | *red* | The asset is unsupported. | *hash* was is unsupported *[by <key/list of keys/org>]* | The signature on the blockchain indicates that the signer DOES NOT trust that asset because it is not supported anymore (eg. deprecated).

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
