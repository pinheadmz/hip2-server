# HIP2-server

## Derive new receive address from xpub with every request

### Configuration

#### Get your wallet account's XPUB

It's reccomended to create a new wallet for your HIP2 server.

https://hsd-dev.org/api-docs/#get-account-information

##### hsd
`hsw-cli --id=<WALLET NAME> account get default | jq accountKey`

##### Bob Wallet
- Get your API key from Settings > Wallet then use hs-client:

`hsw-cli --id=<WALLET NAME> --api-key=<API KEY> account get default | jq -r .accountKey`

##### Paste the xpub by itself into the file in this repo: `conf/xpub`

### Installation & Execution

This package has been pre-built from hsd modules and requires no additional
packages or C compiler, etc. Just run the build with a port number


```
git clone https://github.com/pinheadmz/hip2-server
node hip2-server/build/hip2-server.js 8080
```

Check:
```
--> curl 127.0.0.1:8080
hs1q9f5d5jzhqynzamca4g8arm8qv8s9sc9lly7h7d 
--> curl 127.0.0.1:8080
hs1q7z7w94kwja70qfwav0vxzfff0mk653jrllcq7y 
--> curl 127.0.0.1:8080
hs1q22rl34g6s8f2druz2v7wvrlq39g8d0satydzz7
```

HIP2-server will track the number of requests in the file `log/hip2-index`.
This value may be needed to fully recover all payments made to your account
since many users may make requests without sending payments.

### NGINX



### Build from source

Don't trust my build? fine. Requires C compiler and whatever else `hsd` wants.

```
git clone https://github.com/pinheadmz/hip2-server
cd hip2-server
npm install
npm run build
```