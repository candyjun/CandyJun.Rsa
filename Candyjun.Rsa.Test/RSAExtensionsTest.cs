using CandyJun.Rsa;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;

namespace Candyjun.Rsa.Test
{
    [TestClass]
    public class RSAExtensionsTest
    {
        string privateKey;
        string publicKey;
        public RSAExtensionsTest()
        {
            var generator = new RsaKeyPairGenerator();
            var secureRandom = new SecureRandom();
            //secureRandom.SetSeed(seed);
            generator.Init(new KeyGenerationParameters(secureRandom, 2048));
            var pair = generator.GenerateKeyPair();

            var twPrivate = new StringWriter();
            PemWriter pwPrivate = new PemWriter(twPrivate);
            pwPrivate.WriteObject(pair.Private);
            pwPrivate.Writer.Flush();
            privateKey = twPrivate.ToString();
            Console.WriteLine("Private Key£º" + privateKey);

            var twPublic = new StringWriter();
            PemWriter pwPublic = new PemWriter(twPublic);
            pwPublic.WriteObject(pair.Public);
            pwPublic.Writer.Flush();
            publicKey = twPublic.ToString();
            Console.WriteLine("Public Key£º" + publicKey);
        }
        [TestMethod]
        public void TestEncryptString()
        {
            var provider = RSA.Create();
            provider.FromPemPublicKeyString(publicKey);
            var str = "1";
            var encStr = provider.EncryptString(str, "RSA");

            var provider2 = RSA.Create();
            provider2.FromPemPrivateKeyString(privateKey);
            var sourceStr = provider2.DecryptString(encStr, "RSA");
            Assert.AreEqual(str, sourceStr);
        }

        [TestMethod]
        public void TestSignString()
        {
            var provider = RSA.Create();
            provider.FromPemPrivateKeyString(privateKey);
            var str = "1";
            var encStr = provider.SignString(str, "RSA");

            var provider2 = RSA.Create();
            provider2.FromPemPublicKeyString(publicKey);
            var verifyResult = provider2.VerifyString(str, "RSA", encStr);
            Assert.IsTrue(verifyResult);
        }
    }
}
