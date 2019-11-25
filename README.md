Demonstration of "Collusion Resistant Broadcast Encryption With
Short Ciphertexts and Private Keys" [BGW05](https://eprint.iacr.org/2005/018.pdf)

# install
this code depends on [mcl-wasm](https://github.com/herumi/mcl-wasm) and other modules. Install them with:
```
npm i
```

# test
```
node src/bgw.js
```
Demonstrate the special case:
* setup a system of `n` users, run time and public key size linear with `n` (64 bytes, 2.4 ms per user.)
* create a random set `S` of users that will be allowed to decrypt.
* create a random encryption key `K` and encrypt it. Run time linear with `|S|` (12usec per user)
* select `ntrial` random users and check that only users in `S` can decrypt and retrieve `K`. Run time linear with `|S|` (4usec per user)

The general construction is achieved by splitting the users into shards of size `n` and splitting `S` accordingly. You can use the same public key in each shard except for a different `gamma`in each shard. So now all sizes are proportional to the shard size. 
