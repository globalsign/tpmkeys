/*
Copyright (c) 2020 GMO GlobalSign, Inc.

Licensed under the MIT License (the "License"); you may not use this file except
in compliance with the License. You may obtain a copy of the License at

https://opensource.org/licenses/MIT

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
Package tpmkeys provides an implementation of crypto.Signer and crypto.Decrypter
for a private key resident on a TPM 2.0 (Trusted Platform Module) device.

It is designed for use with the google/go-tpm/tpm2 package and enables
TPM-resident keys to be used transparently with Go standard library packages
such as crypto and tls.
*/
package tpmkeys
