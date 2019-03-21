# CandyJun.Rsa
A .NET Core RSA extensions.
1.Extensions of RSA
2.Converter for RSA key
3.Compatible with Java

Thanks for bcgit's [bc-csharp](https://github.com/bcgit/bc-csharp "bc-csharp")

[![Latest version](https://img.shields.io/nuget/v/CandyJun.Rsa.svg?style=flat-square)](https://www.nuget.org/packages/CandyJun.Rsa/)
# Install

````shell
Install-Package CandyJun.Rsa
````

# Demo

## Generat a pair of key
```
var generator = new RsaKeyPairGenerator();
var secureRandom = new SecureRandom();
generator.Init(new KeyGenerationParameters(secureRandom, 2048));
var pair = generator.GenerateKeyPair();
string privatePemKey;
using (var twPrivate = new StringWriter())
{
    var pwPrivate = new PemWriter(twPrivate);
    pwPrivate.WriteObject(pair.Private);
    pwPrivate.Writer.Flush();
    privatePemKey = twPrivate.ToString();
    Console.WriteLine("Private Key£º" + privatePemKey);
}
string publicKey;
using (var twPublic = new StringWriter())
{
    PemWriter pwPublic = new PemWriter(twPublic);
    pwPublic.WriteObject(pair.Public);
    pwPublic.Writer.Flush();
    publicKey = twPublic.ToString();
    Console.WriteLine("Public Key£º" + publicKey);
}
```
## Encrypt and sign
```
var provider = RSA.Create();
//load cert from private key by pem format 
provider.FromPemPrivateKeyString(privatePemKey);
var str = "test";
//encrypt with enum params: rsa/pkcs7
var encStr = provider.Encrypt(str, CipherMode.NONE, CipherPadding.PKCS7);
//sian with md5
var signStr = provider.SignData(encStr, HashAlgorithm.MD5);
```
## Decrypt and verify
```
var provider2 = RSA.Create();
//load cert from xml, witch convert from another provider export
provider2.FromXmlStringCore(provider.ToXmlStringCore(true));
var verifyResult = provider2.VerifyData(encStr, "MD5WITHRSA", signStr);
//decrypt with string params
var sourceStr = provider2.Decrypt(encStr, "RSA//PKCS7PADDING");
```

# Reference component

 [bc-csharp](https://github.com/bcgit/bc-csharp "bc-csharp") - bcgit

# Change Log

## v1.0.0

### Features
- Add project

## v1.0.1

### Features
- Add enum params