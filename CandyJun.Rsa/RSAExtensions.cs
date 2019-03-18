using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace CandyJun.Rsa
{
    /// <summary>
    /// RSA 扩展类
    /// </summary>
    public static class RSAExtensions
    {
        #region Key
        /// <summary>
        /// 加载XML格式密钥
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="xmlString">XML格式密钥</param>
        public static void FromXmlString2(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);
            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = Convert.FromBase64String(node.InnerText); break;
                        case "Exponent": parameters.Exponent = Convert.FromBase64String(node.InnerText); break;
                        case "P": parameters.P = Convert.FromBase64String(node.InnerText); break;
                        case "Q": parameters.Q = Convert.FromBase64String(node.InnerText); break;
                        case "DP": parameters.DP = Convert.FromBase64String(node.InnerText); break;
                        case "DQ": parameters.DQ = Convert.FromBase64String(node.InnerText); break;
                        case "InverseQ": parameters.InverseQ = Convert.FromBase64String(node.InnerText); break;
                        case "D": parameters.D = Convert.FromBase64String(node.InnerText); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        /// <summary>
        /// RSA加载PrivateKey
        /// </summary>
        /// <param name="privateKey">私钥key</param>
        /// <returns></returns>
        public static void FromPrivateKeyString(this RSA rsa, string privateKey)
        {
            string xmlPrivateKey = RSAKeyConvert.ConvertPrivateKeyToXml(privateKey);
            rsa.FromXmlString2(xmlPrivateKey);
        }

        /// <summary>
        /// RSA加载PublicKey
        /// </summary>
        /// <param name="pemPublicKey">公钥key</param>
        /// <returns></returns>
        public static void FromPemPublicKeyString(this RSA rsa, string pemPublicKey)
        {
            var publicKey = pemPublicKey.Replace("-----BEGIN PUBLIC KEY-----", "").Replace("-----END PUBLIC KEY-----", "").Replace("\n", "").Replace("\r", "");
            rsa.FromPublicKeyString(publicKey);
        }

        /// <summary>
        /// RSA加载PrivateKey
        /// </summary>
        /// <param name="pemPrivateKey">私钥key</param>
        /// <returns></returns>
        public static void FromPemPrivateKeyString(this RSA rsa, string pemPrivateKey)
        {
            AsymmetricCipherKeyPair keyPair;
            using (var sr = new StreamReader(new MemoryStream(Encoding.UTF8.GetBytes(pemPrivateKey))))
            {
                var pemReader = new Org.BouncyCastle.OpenSsl.PemReader(sr);
                keyPair = (AsymmetricCipherKeyPair)pemReader.ReadObject();
            }
            var key = (RsaPrivateCrtKeyParameters)keyPair.Private;
            var p = new RSAParameters
            {
                Modulus = key.Modulus.ToByteArrayUnsigned(),
                Exponent = key.PublicExponent.ToByteArrayUnsigned(),
                D = key.Exponent.ToByteArrayUnsigned(),
                P = key.P.ToByteArrayUnsigned(),
                Q = key.Q.ToByteArrayUnsigned(),
                DP = key.DP.ToByteArrayUnsigned(),
                DQ = key.DQ.ToByteArrayUnsigned(),
                InverseQ = key.QInv.ToByteArrayUnsigned(),
            };

            rsa.ImportParameters(p);
        }

        /// <summary>
        /// RSA加载pkcs证书(.pfx文件)
        /// </summary>
        /// <param name="pkcs12FileContents">证书文件</param>
        /// <param name="includePrivateParameters">是否包含私钥</param>
        /// <returns></returns>
        public static void FromPkcs12Bytes(this RSA rsa, byte[] pkcs12FileContents, bool includePrivateParameters, string password = null)
        {
            string xmlPrivateKey = RSAKeyConvert.ConvertPrivateKeyPkcs12ToXml(pkcs12FileContents, includePrivateParameters, password);
            rsa.FromXmlString2(xmlPrivateKey);
        }

        /// <summary>
        /// 导出XML格式密钥
        /// </summary>
        /// <param name="rsa"></param>
        /// <param name="includePrivateParameters">是否包含私钥</param>
        /// <returns></returns>
        public static string ToXmlString2(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            if (includePrivateParameters)
            {
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
            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                    Convert.ToBase64String(parameters.Modulus),
                    Convert.ToBase64String(parameters.Exponent));
        }

        /// <summary>
        /// RSA导出PrivateKey
        /// </summary>
        public static string ToPrivateKeyString(this RSA rsa)
        {
            RSAParameters parameters = rsa.ExportParameters(true);

            BigInteger m = new BigInteger(1, parameters.Modulus);
            BigInteger exp = new BigInteger(1, parameters.Exponent);
            BigInteger d = new BigInteger(1, parameters.D);
            BigInteger p = new BigInteger(1, parameters.P);
            BigInteger q = new BigInteger(1, parameters.Q);
            BigInteger dp = new BigInteger(1, parameters.DP);
            BigInteger dq = new BigInteger(1, parameters.DQ);
            BigInteger qinv = new BigInteger(1, parameters.InverseQ);

            RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);
            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();
            return Convert.ToBase64String(serializedPrivateBytes);
        }

        /// <summary>
        /// RSA加载PublicKey
        /// </summary>
        /// <param name="publicKey">公钥key</param>
        /// <returns></returns>
        public static void FromPublicKeyString(this RSA rsa, string publicKey)
        {
            string xmlpublicKey = RSAKeyConvert.ConvertPublicKeyToXml(publicKey);
            rsa.FromXmlString2(xmlpublicKey);
        }

        /// <summary>
        /// RSA加载PublicCert(.cer和.der格式证书)
        /// </summary>
        /// <param name="publicCert">公钥key</param>
        /// <returns></returns>
        public static void FromPublicCert(this RSA rsa, byte[] publicCert)
        {
            string xmlpublicKey = RSAKeyConvert.ConvertPublicCertToXml(publicCert);
            rsa.FromXmlString2(xmlpublicKey);
        }

        /// <summary>
        /// RSA导出PublicKey
        /// </summary>
        public static string ToPublicKeyString(this RSA rsa)
        {
            RSAParameters parameters = rsa.ExportParameters(false);
           
            BigInteger m = new BigInteger(1, parameters.Modulus);
            BigInteger p = new BigInteger(1, parameters.Exponent);
            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();
            return Convert.ToBase64String(serializedPublicBytes);
        }
        #endregion

        #region Method
        /// <summary>
        /// 使用公钥加密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待加密的字符串(将以UTF8格式编码加密)</param>
        /// <param name="hashAlgorithm">加密算法和填充模式</param>
        /// <returns>base64编码的加密后数据</returns>
        public static string EncryptString(this RSA provider, string data, string hashAlgorithm)
        {
            return provider.EncryptString(data, hashAlgorithm, Encoding.UTF8);
        }

        /// <summary>
        /// 使用公钥加密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待加密的字符串</param>
        /// <param name="hashAlgorithm">加密算法和填充模式</param>
        /// <param name="encoding">字符串编码格式</param>
        /// <returns>base64编码的加密后数据</returns>
        public static string EncryptString(this RSA provider, string data, string hashAlgorithm, Encoding encoding)
        {
            return Convert.ToBase64String(provider.Encrypt(encoding.GetBytes(data), hashAlgorithm));
        }

        /// <summary>
        /// 使用公钥加密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待加密的数据</param>
        /// <param name="hashAlgorithm">加密算法和填充模式</param>
        /// <returns>加密后的数据</returns>
        public static byte[] Encrypt(this RSA provider, byte[] data, string hashAlgorithm)
        {
            var publicKey = provider.ToPublicKeyString();
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            var cipher = CipherUtilities.GetCipher(hashAlgorithm);
            cipher.Init(true, publicKeyParam);
            return cipher.DoFinal(data);
        }

        /// <summary>
        /// 使用私钥解密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待解密的字符串(base64格式)</param>
        /// <param name="hashAlgorithm">解密算法和填充模式</param>
        /// <returns>原始字符串(将以UTF8格式解码)</returns>
        public static string Decrypt(this RSA provider, string data, string hashAlgorithm)
        {
            return provider.Decrypt(data, hashAlgorithm, Encoding.UTF8);
        }

        /// <summary>
        /// 使用私钥解密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待解密的字符串(base64格式)</param>
        /// <param name="hashAlgorithm">解密算法和填充模式</param>
        /// <returns>原始字符串</returns>
        public static string Decrypt(this RSA provider, string data, string hashAlgorithm, Encoding encoding)
        {
            return encoding.GetString(provider.Decrypt(Convert.FromBase64String(data), hashAlgorithm));
        }

        /// <summary>
        /// 使用私钥解密
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待解密的数据</param>
        /// <param name="hashAlgorithm">解密算法和填充模式</param>
        /// <returns>原始数据</returns>
        public static byte[] Decrypt(this RSA provider, byte[] data, string hashAlgorithm)
        {
            var privateKey = provider.ToPrivateKeyString();
            RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            var cipher = CipherUtilities.GetCipher(hashAlgorithm);
            cipher.Init(false, privateKeyParam);
            return cipher.DoFinal(data);
        }

        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待签名的字符串(将以UTF8格式编码加密)</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <returns>签名后字符串(base64格式)</returns>
        public static string SignData(this RSA provider, string data, string hashAlgorithm)
        {
            return provider.SignData(data, hashAlgorithm, Encoding.UTF8);
        }

        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待签名的字符串</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <param name="encoding">待签名的字符串编码格式</param>
        /// <returns>签名后字符串(base64格式)</returns>
        public static string SignData(this RSA provider, string data, string hashAlgorithm, Encoding encoding)
        {
            return Convert.ToBase64String(provider.SignData(encoding.GetBytes(data), hashAlgorithm));
        }

        /// <summary>
        /// 使用私钥签名
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">待签名的数据</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <returns>签名后数据</returns>
        public static byte[] SignData(this RSA provider, byte[] data, string hashAlgorithm)
        {
            var privateKey = provider.ToPrivateKeyString();
            RsaKeyParameters privateKeyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));
            var signer = SignerUtilities.GetSigner(hashAlgorithm);
            signer.Init(true, privateKeyParam);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.GenerateSignature();
        }

        /// <summary>
        /// 使用公钥验签
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">原始数据(将以UTF8格式编码)</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <param name="signature">签名后数据(base64格式)</param>
        /// <returns></returns>
        public static bool VerifyData(this RSA provider, string data, string hashAlgorithm, string signature)
        {
            return provider.VerifyData(data, hashAlgorithm, signature, Encoding.UTF8);
        }

        /// <summary>
        /// 使用公钥验签
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">原始数据</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <param name="signature">签名后数据(base64格式)</param>
        /// <param name="encoding">原始数据编码格式</param>
        /// <returns></returns>
        public static bool VerifyData(this RSA provider, string data, string hashAlgorithm, string signature, Encoding encoding)
        {
            return provider.VerifyData(encoding.GetBytes(data), hashAlgorithm, Convert.FromBase64String(signature));
        }

        /// <summary>
        /// 使用公钥验签
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="data">原始数据</param>
        /// <param name="hashAlgorithm">签名算法和填充模式</param>
        /// <param name="signature">签名后数据</param>
        /// <returns></returns>
        public static bool VerifyData(this RSA provider, byte[] data, string hashAlgorithm, byte[] signature)
        {
            var publicKey = provider.ToPublicKeyString();
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));
            var signer = SignerUtilities.GetSigner(hashAlgorithm);
            signer.Init(false, publicKeyParam);
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
        #endregion
    }
}
