# Notarization

Notarization is the process initiated by a user (*the signer*), usually by running one of the following commands on an asset:

- `vcn notarize` to notarize an asset so its [status](#Statuses) equals **TRUSTED**
- `vcn untrust` to notarize an asset so its [status](#Statuses) equals **UNTRUSTED**
- `vcn unsupport` to notarize an asset so its [status](#Statuses) equals **UNSUPPORTED**

When the process starts, a fingerprint (the digest or simply *the hash*) is derived from the block of digital data (*the asset*) given as an input by using the [SHA-256](https://en.wikipedia.org/wiki/SHA-2) hashing function.

The hash (not the asset itself, which is never uploaded to nor shared with CodeNotary) alongside with the desired [status](#Statuses) is then cryptographically signed by using the the user's secret and stored on the [ZTC](https://zerotrustconsortium.org/) blockchain. There it remains forever and can never be changed, so it can be used to check the asset authenticity (i.e. invoking `vcn authenticate`) at any point in the future.

In the end, the output of notarization process is a new blockchain entry with the hash bound to the following attributes:

Field | Label | Description 
------------ | ------------- | ------------- 
`Owner` | **Key** | The public address derived from the user's secret, also known as the signer's key.
`Level` | **Level** | The signer's [level](#Levels) at the time when the notarization was made.
`Status` | **Status** | The asset's [status](#Statuses) chosen by the signer at the time when the notarization was made.
`Timestamp` | **Date** | The date and time of the notarization.
> *Field*s are names used to map [the data stored onto the blockchain](https://github.com/vchain-us/vcn/blob/0.5.0/pkg/api/verify.go#L26), *Label*s are used by `vcn` when printing results.

## Authentication

Authentication is the process of confirming an asset's [status](#Statuses) that is recorded on the blockchain. This is usually done by running `vcn authenticate` against the asset.

Given an asset as an input, the hash is computed in the same way it is in the notarization process. Then, if any blockchain entry matches the newly calculated hash , the matching result [status](#Statuses) is returned (the authentication). Otherwise the returned result  [status](#Statuses) equals **UNKNOWN**.

> By default, `vcn` tries to retrieve the last entry matching the current user (if logged in), if not found the last entry with highest [level](#Levels) is returned instead. Alternatively, it is also possible to retrive the authentication matching a specific signer (an user or an organization). 

# Authentication of Co-notarized Assets

`vcn` allows multiple users to notarize the same asset. The act is known as co-notarization. By default, when running vcn authenticate,a user’s last blockchain entry for the asset will be returned to them when logged in, regardless if the asset was co-notarized. However, all other users will be returned the last blockchain entry made by the user with the highest trust level. 

Alternatively, it is also possible to retrieve the authentication matching a specific signer (a user or an organization) using the flag --key.

## Statuses

Code | Status | Color | Description | Error message | Explanation
------------ | ------------- | ------------- | ------------ | ------------- | -------------
0 | **TRUSTED** | *green* | The asset was notarized. | *none* | The blockchain indicates that the asset is authentic and the signer trusts it.
2 | **UNKNOWN** | *yellow* | The asset is not notarized. | *hash* is not notarized *[by <key/list of keys/org>]* | No notarization is found on the blockchain for the asset.
1 | **UNTRUSTED** | *red* | The asset is untrusted. | *hash* is untrusted *[by <key/list of keys/org>]* | The  blockchain indicates that the signer DOES NOT trust the asset.
3 | **UNSUPPORTED** | *red* | The asset is unsupported. | *hash* is unsupported *[by <key/list of keys/org>]* | The blockchain indicates that the signer DOES NOT trust the asset because it is not supported anymore (e.g. deprecated).

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

## FAQs

### Who/what is performing the act of notarization?

  Notarization is performed by a combination of user action, CodeNotary OpenSource software, and a CodeNotary smart contract.
 
### Who is the witness?

  The CodeNotary smart contract and every member node of ZTC blockchain are the witnesses who attest to the authenticity of the records stored on the blockchain. 
 
### Who guarantees that nothing gets changed after the notarization has been processed?

  The blockchain and the collective protection of the ZTC member nodes guarantee the records stored on the blockchain are forever immutable and authentic.
 
### Who is the ZTC?
 
  The [ZTC](https://zerotrustconsortium.org/) (Zero Trust Consortium) is the software industry’s first blockchain-based consortium that adheres to a community-led, group governance model. Its decentralized design prevents any one member from dominating control over the others, allowing verified truth to only come through group consensus. No member has the ability to unilaterally adjust, role back, or delete the history that has been recorded. The consortium makes its ledger available to the public for inspection year round, day or night. 

