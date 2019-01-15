# vcn-cli

Global, de-centralized certification of digital assets

## Development



Clone this directory into your `GOPATH`, usually this is `$HOME/go/src/`

### PATH

```
$> export GOPATH=$HOME/go
$> export GOBIN=$GOPATH/bin
$> PATH=$PATH:$GOPATH:$GOBIN
$> export PATH
```

or simply put it to `$HOME/.bash_profile` once.

### Installation

Install vcn system-wide.

```
$> cd vcn-cli/vcn
$> go install
```

## Usage

```
$> vcn --help
$> vcn commit <file> [user]:[password]
$> vcn verify <file>
```

## Distribution

### Cross-compiling for various platforms

The C libraries of go-etehreum make a more sophisticated cross-compilation
necessary. Make sure you have `xgo` installed:

```
go get -u github.com/karalabe/xgo
```

`./build-multiplatform.sh` in `dist` takes care of the rest.


### Old school

Building the application for different platforms
```
$> env GOOS=windows GOARCH=amd64 go build vcn.go 
```
c.f. [Digital Ocean multi-platform guide](https://www.digitalocean.com/community/tutorials/how-to-build-go-executables-for-multiple-platforms-on-ubuntu-16-04)


## Book

Check this out: https://github.com/miguelmota/ethereum-development-with-go-book