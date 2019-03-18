using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.IO;
using System.Security.Cryptography;

namespace CandyJun.Rsa.Test
{
    [TestClass]
    public class RSAKeyConvertTest
    {
        string privateKey;
        byte[] pkcs12FileContents;
        byte[] publicCer;
        public RSAKeyConvertTest()
        {
            privateKey = File.ReadAllText("TestData\\server.key");
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            pkcs12FileContents = File.ReadAllBytes("TestData\\server.pfx");
            publicCer = File.ReadAllBytes("TestData\\server.public.cer");
        }

        [TestMethod]
        public void TestConvertPrivateKeyToXml()
        {
            var xml = RSAKeyConvert.ConvertPrivateKeyToXml(privateKey);
            var rsa = RSA.Create();
            rsa.FromXmlStringCore(xml);
            Assert.IsNotNull(rsa.ExportParameters(true));
        }

        [TestMethod]
        public void TestConvertXmlToPrivateKey()
        {
            var xmlKeyml = RSAKeyConvert.ConvertPrivateKeyToXml(privateKey);
            var key = RSAKeyConvert.ConvertXmlToPrivateKey(xmlKeyml);

            Assert.AreEqual(key, privateKey);
        }

        [TestMethod]
        public void TestConvertPrivateKeyXmlToPkcs1()
        {
            var xmlKey = RSAKeyConvert.ConvertPrivateKeyPkcs12ToXml(pkcs12FileContents, true);
            var pkcs1Key = RSAKeyConvert.ConvertPrivateKeyXmlToPkcs1(xmlKey);
            var xmlKeyFrom1 = RSAKeyConvert.ConvertPrivateKeyPkcs1ToXml(pkcs1Key);
            Assert.AreEqual(xmlKey, xmlKeyFrom1);
            var pkcs8KeyFromXml = RSAKeyConvert.ConvertPrivateKeyXmlToPkcs8(xmlKey);
            var pkcs8Key = RSAKeyConvert.ConvertPrivateKeyPkcs1ToPkcs8(pkcs1Key);
            Assert.AreEqual(pkcs8Key, pkcs8KeyFromXml);
            var pkcs1KeyFrom8 = RSAKeyConvert.ConvertPrivateKeyPkcs8ToPkcs1(pkcs8Key);
            Assert.AreEqual(pkcs1Key, pkcs1KeyFrom8);
            var xmlKeyFrom8 = RSAKeyConvert.ConvertPrivateKeyPkcs8ToXml(pkcs8Key);
            Assert.AreEqual(xmlKeyFrom8, xmlKey);
            var pubFromPri = RSAKeyConvert.ConvertXmlToPublicKey(xmlKey);
            var publicCerXml = RSAKeyConvert.ConvertPublicCertToXml(publicCer);
            var pubFromCer = RSAKeyConvert.ConvertXmlToPublicKey(publicCerXml);
            Assert.AreEqual(pubFromPri, pubFromCer);
        }
    }
}
