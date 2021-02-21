# tpmkeys

[![GoDoc](https://godoc.org/github.com/globalsign/tpmkeys?status.svg)](https://godoc.org/github.com/globalsign/tpmkeys)
[![Build Status](https://github.com/globalsign/tpmkeys/actions/workflows/go.yml/badge.svg)](https://github.com/globalsign/tpmkeys/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/globalsign/tpmkeys)](https://goreportcard.com/report/github.com/globalsign/tpmkeys)

Package tpmkeys provides an implementation of crypto.Signer and crypto.Decrypter
for private keys resident on a TPM 2.0 (Trusted Platform Module) device.

It is designed for use with the [google/go-tpm/tpm2 package](https://github.com/google/go-tpm) and enables
TPM-resident keys to be used transparently with Go standard library packages such
as `crypto` and `tls`.

## Install

    go get github.com/globalsign/tpmkeys

## License

Copyright (c) 2020-present [GMO GlobalSign, Inc.](https://github.com/globalsign)

Licensed under [MIT License](./LICENSE)
