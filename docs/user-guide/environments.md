# Environments

By default `vcn` will put the config file and secret keys within the a directory called `.vcn` within your `$HOME`.
However, `vcn` can work with distinct envirnoments (eg. for testing purpose).

The following environments are supported by setting the `STAGE` envirnoment var:

Stage | Directory | Note
------------ | ------------- | -------------
`STAGE=PRODUCTION` | `~/.vcn` | *default* 
`STAGE=STAGING` | `~/.vcn.staging` |
`STAGE=TEST` | `~/vcn.test` | *`VCN_TEST_DASHBOARD`, `VCN_TEST_NET`, `VCN_TEST_CONTRACT`, `VCN_TEST_API` must be set accordingly to your test environment*

## Other environment variables

Name | Description | Example 
------------ | ------------- | -------------
`VCN_USER`, `VCN_PASSWORD` | Credentials for non-interactive user login | `VCN_USER=example@example.net VCN_PASSWORD=<your_password> vcn login`
`VCN_KEY` | List of keys to verify against | `VCN_KEY="0x0...0 0x0...1" vcn verify <asset>`
`VCN_ORG` | Organization's ID to verify against | `VCN_ORG="vchain.us" vcn verify <asset>`
`KEYSTORE_PASSWORD` | Keystore's passphrase for non-interactive signing | `KEYSTORE_PASSWORD=<your_passphrase> vcn sign <asset>`
`LOG_LEVEL` | Logging verbosity. Accepted values: `TRACE, DEBUG, INFO, WARN, ERROR, FATAL, PANIC`  | `LOG_LEVEL=TRACE vcn login` 
`HTTP_PROXY` | HTTP Proxy configuration | `HTTP_PROXY=http://localhost:3128 vcn verify <asset>`