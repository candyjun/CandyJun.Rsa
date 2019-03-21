using System;
using System.IO;
using System.Security.Cryptography;
using CandyJun.Rsa;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace CandyJun.Rsa.Demo
{
    class Program
    {
        static void Main(string[] args)
        {
            //generat a pair of key
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
                Console.WriteLine("Private Key：" + privatePemKey);
            }
            string publicKey;
            using (var twPublic = new StringWriter())
            {
                PemWriter pwPublic = new PemWriter(twPublic);
                pwPublic.WriteObject(pair.Public);
                pwPublic.Writer.Flush();
                publicKey = twPublic.ToString();
                Console.WriteLine("Public Key：" + publicKey);
            }

            var provider = RSA.Create();
            //load cert from private key by pem format 
            provider.FromPemPrivateKeyString(privatePemKey);
            var str = "test";
            Console.WriteLine("Source：" + str);
            //encrypt with enum params: rsa/pkcs7
            var encStr = provider.Encrypt(str, CipherMode.NONE, CipherPadding.PKCS7);
            Console.WriteLine("Encrypt：" + encStr);
            //sian with md5
            var signStr = provider.SignData(encStr, HashAlgorithm.MD5);
            Console.WriteLine("Sign：" + signStr);

            var provider2 = RSA.Create();
            //load cert from xml, witch convert from another provider export
            provider2.FromXmlStringCore(provider.ToXmlStringCore(true));
            var verifyResult = provider2.VerifyData(encStr, "MD5WITHRSA", signStr);
            Console.WriteLine("Verify：" + verifyResult);
            //decrypt with string params
            var sourceStr = provider2.Decrypt(encStr, "RSA//PKCS7PADDING");
            Console.WriteLine("Decrypt：" + sourceStr);

            Console.ReadKey();
        }
    }
}
