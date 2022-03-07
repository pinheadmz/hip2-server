# HIP2-server

## Derive new receive address from xpub with every request

### Configuration

#### Get your wallet account's XPUB

It's reccomended to create a new wallet for your HIP2 server.

https://hsd-dev.org/api-docs/#get-account-information

##### hsd
`hsw-cli --id=<WALLET NAME> account get default | jq -r .accountKey`

##### Bob Wallet
- Get your API key from Settings > Wallet then use hs-client:

`hsw-cli --id=<WALLET NAME> --api-key=<API KEY> account get default | jq -r .accountKey`

##### Paste the xpub by itself into the file in this repo: `conf/xpub`

### Installation & Execution

This package has been pre-built from hsd modules and requires no additional
packages or C compiler, etc. Just run the build with a port number


```
git clone https://github.com/pinheadmz/hip2-server
cd hip2-server
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

If you are using nginx as your webserver, you can configure one or even many
domains to use the same HIP2 server, and even redirect to a hard-coded flat
file (with single HNS address) in case the HIP2 server crashes!

In this example, port `60000` is the nodeJS webserver actually running the
`proofofconcept` website, which has a [hard-coded HIP2 address](https://github.com/pinheadmz/proofofconcept/blob/master/html/.well-known/wallets/HNS).

By using the `proxy_pass` and `error_page` directives in the nginx configuration,
the HIP2 address will by default come from HIP2-server but fall back to the flat
file in case of failure.


```
server {
  server_name *.proofofconcept proofofconcept;

  listen 443 ssl;
  listen [::]:443 ssl;

  ssl_certificate /root/ssl/proofofconcept/cert.crt;
  ssl_certificate_key /root/ssl/proofofconcept/cert.key;

  location / {
    proxy_pass         http://localhost:60000;
    proxy_set_header   Host $host;
  }

  location @main {
    proxy_pass         http://localhost:60000;
    proxy_set_header   Host $host;
  }

  location /.well-known/wallets/HNS {
    proxy_pass  http://localhost:20000;
    error_page  500 502  @main;
  }
}
```

### Build from source

Don't trust my build? fine. Requires C compiler and whatever else `hsd` wants.

```
git clone https://github.com/pinheadmz/hip2-server
cd hip2-server
npm install
npm run build
```

### Wallet recovery and pitfalls

The default `lookahead` value in hsd is 200. That means that if at least one
out of every 200 HIP2 address requests results in an on-chain transaction,
the original wallet (or new wallet rescanning from the original seed) will
recover all payments. Users should monitor the value saved to `log/hip2-index`
and if it gets too large you may need to manually generate addresses in the
recovery wallet before rescanning. After the hip2-server serves `0x7fffffff`
addresses, it will start over at index `0` and recycle. The `log/hip2-index`
file will continue to increment, so users should also take action if they see
the value in that file exceed `2147483647`.
