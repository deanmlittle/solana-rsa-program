# Solana RSA program

This program leverages the built-in hashing syscalls along with the new modular exponentiation syscall to bring on-chain RSA signature verification to Solana.

# Building

There are two liibraries in here, one being the rust program itself, and the other being the typescript library to help form vailid RSA program instructions. You can build them respectively like so:

`yarn build:rust`

`yarn build:typescript`

or to build both from source:

`yarn build`

# Testing

There are unit tests implemented in Rust which can be run using:

`cargo test`

There are also integration tests written in Typescript which can be run using:

`yarn test`

Please note: You must have the program deployed to run the tests.

# Deployment

After running build, you can deploy the RSA program to your local validator using:

`yarn deploy:localhost`

Or to whichever environment is currently configured in your solana CLI using:

`yarn deploy`

# Caveats

### Data constraints

RSA signatures and public keys are quite large compared to their EC bretheren. As such, it can be quite easy to overload the instruction data. One way around this is to store your message and public key onchain ahead of time, meaning only the signature needs to be provided at the time of calling the function. As the RSA program is just a regular program and not a precompile, it is available via CPI. An instruction for this is included in the Rust code to make your life easier.

### Hashing

We are limited by what we can hash in the SVM, however assuming you find a way to secure your signing scheme offchain without the need for onchain hashing, you can make use of naive signature verification, verifying only that a signature is valid for a particular hash on-chain, but not that a message belongs to a specific hash.

# Contributing

Code contributions and feature requests are welcomed! Submit a PR and we'll see what we can do to make this better.