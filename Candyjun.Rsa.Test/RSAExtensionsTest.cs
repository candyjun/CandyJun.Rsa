using CandyJun.Rsa;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Candyjun.Rsa.Test
{
    [TestClass]
    public class RSAExtensionsTest
    {
        string privateKey;
        byte[] pkcs12FileContents;
        byte[] publicCer;
        public RSAExtensionsTest()
        {
            privateKey = File.ReadAllText("TestData\\server.key");
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            pkcs12FileContents = File.ReadAllBytes("TestData\\server.pfx");
            publicCer = File.ReadAllBytes("TestData\\server.public.cer");
        }

        [TestMethod]
        public void TestEncryptString()
        {
            var provider = RSA.Create();
            provider.FromPublicCert(publicCer);
            var str = "1";
            var encStr = provider.Encrypt(str, "RSA");

            var provider2 = RSA.Create();
            provider2.FromPkcs12Bytes(pkcs12FileContents, true);
            var sourceStr = provider2.Decrypt(encStr, "RSA");
            Assert.AreEqual(str, sourceStr);
        }

        [TestMethod]
        public void TestSignString()
        {
            var provider = RSA.Create();
            provider.FromPrivateKeyString(privateKey);
            var str = "1";
            var encStr = provider.SignData(str, "MD5WITHRSA");

            var provider2 = RSA.Create();
            var pub = RSAKeyConvert.ConvertPublicCertToXml(publicCer);
            pub = RSAKeyConvert.ConvertXmlToPublicKey(pub);
            provider2.FromPemPublicKeyString(RsaPemFormatHelper.PublicKeyFormat(pub));
            var verifyResult = provider2.VerifyData(str, "MD5WITHRSA", encStr);
            Assert.IsTrue(verifyResult);
        }

        [TestMethod]
        public void TestVerifyString()
        {
            var generator = new RsaKeyPairGenerator();
            var secureRandom = new SecureRandom();
            generator.Init(new KeyGenerationParameters(secureRandom, 2048));
            var pair = generator.GenerateKeyPair();
            string privatePemKey;
            using (var twPrivate = new StringWriter())
            {
                PemWriter pwPrivate = new PemWriter(twPrivate);
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

            var provider = RSA.Create();
            provider.FromPemPrivateKeyString(privatePemKey);
            var str = "1";
            var encStr = provider.SignData(str, "MD5WITHRSA");

            var provider2 = RSA.Create();
            provider2.FromXmlStringCore(provider.ToXmlStringCore(true));
            var verifyResult = provider2.VerifyData(str, "MD5WITHRSA", encStr);
            Assert.IsTrue(verifyResult);

            var provider3 = RSA.Create();
            provider3.FromXmlStringCore(provider.ToXmlStringCore(false));
            var verifyResult2 = provider3.VerifyData(
                Encoding.UTF8.GetBytes(str),
                Convert.FromBase64String(encStr),
                HashAlgorithmName.MD5,
                RSASignaturePadding.Pkcs1);
            Assert.IsTrue(verifyResult2);
        }
    }
}
