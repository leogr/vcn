# vcn - vChain CodeNotary [![CircleCI](https://circleci.com/gh/vchain-us/vcn.svg?style=svg)](https://circleci.com/gh/vchain-us/vcn)
> Notarize and authenticate, from code to production

## How it works
![vcn How it works](https://raw.githubusercontent.com/vchain-us/vcn/master/docs/vcn_hiwb.png "How it works")

## Installation

### Binary (Cross-platform)

It's easiest to download the latest version for your platform from the [release page](
https://github.com/vchain-us/vcn/releases).

Once downloaded, you can rename the binary to `vcn`, then run it from anywhere.
> For Linux and macOS you need to mark the file as executable: `chmod +x vcn`

### Homebrew / Linuxbrew

If you are on macOS and using [Homebrew](https://brew.sh/) (or on Linux and using [Linuxbrew](https://linuxbrew.sh/)), you can install `vcn` with the following:

```
brew tap vchain-us/brew
brew install vcn
```

### From Source

After having installed [golang](https://golang.org/doc/install) 1.12 or newer clone this 
repository into your working directory.

#### Build locally

You can build `vcn` in the working directory using the provided `Makefile`.

```
make vcn
```

Then run
```
./vcn
```

#### System-wide

This will put the `vcn` executable into `GOBIN` which is
accessible throughout the system.

```
make install
```

## Usage

For detailed **command line usage** see [docs/cmd/vcn.md](docs/cmd/vcn.md) or just run `vcn help`.


Furthermore, check out our list of **integrations**:

* [docker](docs/DOCKERINTEGRATION.md) - Out of the box support for notarizing and authenticating Docker images.
* [hub.docker.com/r/codenotary/vcn](https://hub.docker.com/r/codenotary/vcn) - The `vcn`'s DockerHub repository. 
* [kube-notary](https://github.com/vchain-us/kube-notary) - A Kubernetes watchdog for verifying image trust with CodeNotary.
* [vcn-watchdog](https://github.com/vchain-us/vcn-watchdog) - Continuous authentication with CodeNotary for Docker.
* [jsvcn](https://github.com/vchain-us/jsvcn) - CodeNotary JavaScript Client.
* [jvcn](https://github.com/vchain-us/jvcn) - CodeNotary Java Bindings.
* [jvcn-maven-plugin](https://github.com/vchain-us/jvcn-maven-plugin) - Maven dependency authentication and enforcement.

### Basic usage

Register an account with [codernotary.io](https://codenotary.io) first.

Then start with the `login` command. `vcn` will walk you through login and setting up your secret upon initial use.
```
vcn login
```

You're good to use `authenticate` without the above registration.

```
vcn authenticate <file>
vcn authenticate dir://<directory>
vcn authenticate docker://<imageId>
vcn authenticate podman://<imageId>
vcn authenticate --hash <hash>
```

Output results in `json` or `yaml` formats:
```
vcn authenticate --output=json <asset>
vcn authenticate --output=yaml <asset>
```
> Check out the [user guide](docs/user-guide/formatted-output.md) for further details.

Once your secret is set you can notarize assets:

```
vcn notarize <file>
vcn notarize dir://<directory>
vcn notarize docker://<imageId>
vcn notarize podman://<imageId>
vcn notarize --hash <hash>
```

By default all assets are notarized private, so not much information is disclosed about the asset. If you want to make that public and therefore, more trusted, please use the `--public` flag.

```
vcn notarize --public <asset>
```

Change the asset's status:

```
vcn unsupport <asset>
vcn untrust <asset>
```

Fetch all assets you've notarized:

```
vcn list
```

Have a look at analytics and extended functionality on the dashboard (browser needed):

```
vcn dashboard
```

### Examples

#### Authenticate a Docker image automatically prior to running it

First, you’ll need to pull the image by using: 

```
docker pull hello-world
```

Then use the below command to put in place an automatic safety check. It allows only verified images to run. 

```
vcn authenticate docker://hello-world && docker run hello-world
```
If an image was not verified, it will not run and nothing will execute. 


#### Authenticate multiple assets
You can authenticate multiple assets by piping other command outputs into `vcn`:
```
ls | xargs vcn authenticate
```
> The exit code will be `0` only if all the assets in you other command outputs are verified.

#### Authenticate by a specific signer
By adding `--key`, you can authenticate that your asset has been signed by a specific signer’s public key address.

```
vcn authenticate --key 0x8f2d1422aed72df1dba90cf9a924f2f3eb3ccd87 docker://hello-world
```

#### Authenticate by a list of signers

If an asset you or your organization wants to trust needs to be verified against a list of signers as a prerequisite, then use the `vcn authenticate` command and the following syntax:

- Add a `--key` flag in front of each key you want to add  
(eg. `--key 0x0...1 --key 0x0...2`)
- Or set the env var `VCN_KEY` correctly by using a space to separate each key (eg. `VCN_KEY=0x0...1 0x0...2`)
> Be aware that using the `--key` flag will take precedence over `VCN_KEY`.

The asset authentication will succeed only if the asset has been signed by at least one of the signers.

#### Authenticate using the asset's hash

If you want to authenticate an asset using only its hash, you can do so by using the command as shown below:

```
vcn authenticate --hash fce289e99eb9bca977dae136fbe2a82b6b7d4c372474c9235adc1741675f587e
```

#### Unsupport/untrust an asset you do not have anymore

In case you want to unsupport/untrust an asset of yours that you no longer have, you can do so using the asset hash(es) with the following steps below.

First, you’ll need to get the hash of the asset from your CodeNotary [dashboard](https://dashboard.codenotary.io/) or alternatively you can use the `vcn list` command. Then, in the CLI, use:

```
vcn untrust --hash <asset's hash>
# or 
vcn unsupport --hash <asset's hash>
```

#### Notarization within automated environments

First, you’ll need to make `vcn` have access to the `${HOME}/.vcn` folder that holds your private keys.
Then, set up your environment accordingly using the following commands:
```
export VCN_USER=<email>
export VCN_PASSWORD=<password>
export KEYSTORE_PASSWORD=<passphrase>
```

Once done, you can use `vcn` in your non-interactive environment using:

```
vcn login
vcn notarize --key <your key> <asset>
```
> Other commands like `untrust` and `unsupport` will also work.


#### Working with Docker and Kubernetes

Check out our integrations:

* [Docker](docs/DOCKERINTEGRATION.md)
* [vcn-watchdog](https://github.com/vchain-us/vcn-watchdog)
* [vcn-k8s](https://github.com/vchain-us/vcn-k8s)


## Configuration
See [docs/user-guide/configuration.md](docs/user-guide/configuration.md).

## Environments
See [docs/user-guide/environments.md](docs/user-guide/environments.md).

## Testing
```
make test
```

## Cross-compiling for various platforms

The C libraries of [go-ethereum](https://github.com/ethereum/go-ethereum) make a more sophisticated cross-compilation
necessary. 
The `make dist` target takes care of all steps by using [xgo](https://github.com/techknowlogick/xgo) and [docker](https://github.com/docker). 

## License

This software is released under [GPL3](https://www.gnu.org/licenses/gpl-3.0.en.html).
