using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Xml;
using System.Xml.Linq;

namespace CandyJun.Rsa
{
    /// <summary>
    /// RSA密钥转换
    /// </summary>
    public static class RSAKeyConvert
    {
        /// <summary>
        ///  把私钥Key转换成xml格式私钥
        /// </summary>
        /// <param name="privateKey">私钥Key</param>
        /// <returns>xml格式私钥</returns>
        public static string ConvertPrivateKeyToXml(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            var privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            string xmlPrivateKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                         Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
                         Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
            return xmlPrivateKey;
        }

        /// <summary>
        ///  把xml格式私钥转换成私钥Key
        /// </summary>
        /// <param name="xmlPrivateKey">xml格式私钥</param>
        /// <returns>私钥Key</returns>
        public static string ConvertXmlToPrivateKey(string xmlPrivateKey)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xmlPrivateKey);
            var m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            var exp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            var d = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
            var p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
            var q = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
            var dp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
            var dq = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
            var qinv = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));

            RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            return Convert.ToBase64String(serializedPrivateBytes);
        }

        /// <summary>
        ///  把pkcs12证书转换成xml格式私钥
        /// </summary>
        /// <param name="pkcs12FileContents">pkcs12证书</param>
        /// <param name="includePrivateParameters">是否包含私钥</param>
        /// <param name="password">私钥密码</param>
        /// <returns>xml格式私钥</returns>
        public static string ConvertPrivateKeyPkcs12ToXml(byte[] pkcs12FileContents, bool includePrivateParameters, string password = null)
        {
            X509Certificate2 cert = new X509Certificate2(pkcs12FileContents, password, X509KeyStorageFlags.Exportable);
            var parameters = cert.GetRSAPrivateKey().ExportParameters(true);
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                    Convert.ToBase64String(parameters.Modulus),
                    Convert.ToBase64String(parameters.Exponent),
                    Convert.ToBase64String(parameters.P),
                    Convert.ToBase64String(parameters.Q),
                    Convert.ToBase64String(parameters.DP),
                    Convert.ToBase64String(parameters.DQ),
                    Convert.ToBase64String(parameters.InverseQ),
                    Convert.ToBase64String(parameters.D));
        }

        /// <summary>
        ///  把私钥Key转换成xml格式私钥
        /// </summary>
        /// <param name="pkcsPrivateKey">私钥Key</param>
        /// <returns>xml格式私钥</returns>
        public static string ConvertPrivateKeyPkcs1ToXml(string pkcsPrivateKey)
        {
            var privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(pkcsPrivateKey);

            PemReader pr = new PemReader(new StringReader(privateKey));
            if (!(pr.ReadObject() is AsymmetricCipherKeyPair asymmetricCipherKeyPair))
            {
                throw new Exception("Private key format is incorrect");
            }
            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters =
                (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(
                    PrivateKeyInfoFactory.CreatePrivateKeyInfo(asymmetricCipherKeyPair.Private));
            var parameters = new
            {
                Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned(),
                Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned(),
                DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned(),
                D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                   Convert.ToBase64String(parameters.Modulus),
                   Convert.ToBase64String(parameters.Exponent),
                   Convert.ToBase64String(parameters.P),
                   Convert.ToBase64String(parameters.Q),
                   Convert.ToBase64String(parameters.DP),
                   Convert.ToBase64String(parameters.DQ),
                   Convert.ToBase64String(parameters.InverseQ),
                   Convert.ToBase64String(parameters.D));
        }

        /// <summary>
        /// 把公钥key转换成xml格式公钥
        /// </summary>
        /// <param name="publicKey">公钥key</param>
        /// <returns>xml格式公钥</returns>
        public static string ConvertPublicKeyToXml(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            string xmlpublicKey = string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
              Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
              Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
            return xmlpublicKey;
        }

        /// <summary>
        /// 把公钥cer证书转换成xml格式公钥
        /// </summary>
        /// <param name="publicCer">公钥cer证书</param>
        /// <returns>xml格式公钥</returns>
        public static string ConvertPublicCertToXml(byte[] publicCer)
        {
            X509Certificate2 cert = new X509Certificate2(publicCer);
            var parameters = cert.GetRSAPublicKey().ExportParameters(false);
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                    Convert.ToBase64String(parameters.Modulus),
                    Convert.ToBase64String(parameters.Exponent));
        }

        /// <summary>
        /// 把xml格式公钥转换成公钥key
        /// </summary>
        /// <param name="xmlPublicKey">xml格式公钥</param>
        /// <returns>公钥key</returns>
        public static string ConvertXmlToPublicKey(string xmlPublicKey)
        {
            var doc = new XmlDocument();
            doc.LoadXml(xmlPublicKey);
            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);
            
            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return Convert.ToBase64String(serializedPublicBytes);
        }

        /// <summary>
        /// Private Key Convert xml->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyXmlToPkcs1(string privateKey)
        {
            XElement root = XElement.Parse(privateKey);
            //Modulus
            var modulus = root.Element("Modulus");
            //Exponent
            var exponent = root.Element("Exponent");
            //P
            var p = root.Element("P");
            //Q
            var q = root.Element("Q");
            //DP
            var dp = root.Element("DP");
            //DQ
            var dq = root.Element("DQ");
            //InverseQ
            var inverseQ = root.Element("InverseQ");
            //D
            var d = root.Element("D");

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                new BigInteger(1, Convert.FromBase64String(d.Value)),
                new BigInteger(1, Convert.FromBase64String(p.Value)),
                new BigInteger(1, Convert.FromBase64String(q.Value)),
                new BigInteger(1, Convert.FromBase64String(dp.Value)),
                new BigInteger(1, Convert.FromBase64String(dq.Value)),
                new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            pWrt.WriteObject(rsaPrivateCrtKeyParameters);
            pWrt.Writer.Close();
            return sw.ToString();
        }
        
        /// <summary>
        /// Private Key Convert Pkcs8->xml
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs8ToXml(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormatRemove(privateKey);
            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters =
                (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            var parameters = new
            {
                Modulus = rsaPrivateCrtKeyParameters.Modulus.ToByteArrayUnsigned(),
                Exponent = rsaPrivateCrtKeyParameters.PublicExponent.ToByteArrayUnsigned(),
                P = rsaPrivateCrtKeyParameters.P.ToByteArrayUnsigned(),
                Q = rsaPrivateCrtKeyParameters.Q.ToByteArrayUnsigned(),
                DP = rsaPrivateCrtKeyParameters.DP.ToByteArrayUnsigned(),
                DQ = rsaPrivateCrtKeyParameters.DQ.ToByteArrayUnsigned(),
                InverseQ = rsaPrivateCrtKeyParameters.QInv.ToByteArrayUnsigned(),
                D = rsaPrivateCrtKeyParameters.Exponent.ToByteArrayUnsigned()
            };
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                   Convert.ToBase64String(parameters.Modulus),
                   Convert.ToBase64String(parameters.Exponent),
                   Convert.ToBase64String(parameters.P),
                   Convert.ToBase64String(parameters.Q),
                   Convert.ToBase64String(parameters.DP),
                   Convert.ToBase64String(parameters.DQ),
                   Convert.ToBase64String(parameters.InverseQ),
                   Convert.ToBase64String(parameters.D));
        }

        /// <summary>
        /// Private Key Convert xml->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyXmlToPkcs8(string privateKey)
        {
            XElement root = XElement.Parse(privateKey);
            //Modulus
            var modulus = root.Element("Modulus");
            //Exponent
            var exponent = root.Element("Exponent");
            //P
            var p = root.Element("P");
            //Q
            var q = root.Element("Q");
            //DP
            var dp = root.Element("DP");
            //DQ
            var dq = root.Element("DQ");
            //InverseQ
            var inverseQ = root.Element("InverseQ");
            //D
            var d = root.Element("D");

            RsaPrivateCrtKeyParameters rsaPrivateCrtKeyParameters = new RsaPrivateCrtKeyParameters(
                new BigInteger(1, Convert.FromBase64String(modulus.Value)),
                new BigInteger(1, Convert.FromBase64String(exponent.Value)),
                new BigInteger(1, Convert.FromBase64String(d.Value)),
                new BigInteger(1, Convert.FromBase64String(p.Value)),
                new BigInteger(1, Convert.FromBase64String(q.Value)),
                new BigInteger(1, Convert.FromBase64String(dp.Value)),
                new BigInteger(1, Convert.FromBase64String(dq.Value)),
                new BigInteger(1, Convert.FromBase64String(inverseQ.Value)));

            StringWriter swpri = new StringWriter();
            PemWriter pWrtpri = new PemWriter(swpri);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(rsaPrivateCrtKeyParameters);
            pWrtpri.WriteObject(pkcs8);
            pWrtpri.Writer.Close();
            return swpri.ToString();

        }

        /// <summary>
        /// Private Key Convert Pkcs1->Pkcs8
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs1ToPkcs8(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs1PrivateKeyFormat(privateKey);
            PemReader pr = new PemReader(new StringReader(privateKey));

            AsymmetricCipherKeyPair kp = pr.ReadObject() as AsymmetricCipherKeyPair;
            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            Pkcs8Generator pkcs8 = new Pkcs8Generator(kp.Private);
            pWrt.WriteObject(pkcs8);
            pWrt.Writer.Close();
            string result = sw.ToString();
            return result;
        }

        /// <summary>
        /// Private Key Convert Pkcs8->Pkcs1
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        public static string ConvertPrivateKeyPkcs8ToPkcs1(string privateKey)
        {
            privateKey = RsaPemFormatHelper.Pkcs8PrivateKeyFormat(privateKey);
            PemReader pr = new PemReader(new StringReader(privateKey));

            RsaPrivateCrtKeyParameters kp = pr.ReadObject() as RsaPrivateCrtKeyParameters;

            var keyParameter = PrivateKeyFactory.CreateKey(PrivateKeyInfoFactory.CreatePrivateKeyInfo(kp));

            StringWriter sw = new StringWriter();
            PemWriter pWrt = new PemWriter(sw);
            pWrt.WriteObject(keyParameter);
            pWrt.Writer.Close();
            string result = sw.ToString();
            return result;
        }
    }
}
