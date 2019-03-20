using System;
using System.Collections.Generic;
using System.Text;

namespace CandyJun.Rsa
{
    /// <summary>
    /// 签名算法
    /// </summary>
    public class SignerAlgorithms
    {
        /// <summary>
        /// 签名算法集合
        /// </summary>
        public static readonly string[] AlgorithmNames = { "MD2WITHRSA", "MD2WITHRSAENCRYPTION", "MD4WITHRSA", "MD4WITHRSAENCRYPTION", "MD5WITHRSA", "MD5WITHRSAENCRYPTION", "SHA1WITHRSA", "SHA1WITHRSAENCRYPTION", "SHA-1WITHRSA", "SHA224WITHRSA", "SHA224WITHRSAENCRYPTION", "SHA-224WITHRSA", "SHA256WITHRSA", "SHA256WITHRSAENCRYPTION", "SHA-256WITHRSA", "SHA384WITHRSA", "SHA384WITHRSAENCRYPTION", "SHA-384WITHRSA", "SHA512WITHRSA", "SHA512WITHRSAENCRYPTION", "SHA-512WITHRSA", "PSSWITHRSA", "RSASSA-PSS", "RSAPSS", "SHA1WITHRSAANDMGF1", "SHA-1WITHRSAANDMGF1", "SHA1WITHRSA/PSS", "SHA-1WITHRSA/PSS", "SHA224WITHRSAANDMGF1", "SHA-224WITHRSAANDMGF1", "SHA224WITHRSA/PSS", "SHA-224WITHRSA/PSS", "SHA256WITHRSAANDMGF1", "SHA-256WITHRSAANDMGF1", "SHA256WITHRSA/PSS", "SHA-256WITHRSA/PSS", "SHA384WITHRSAANDMGF1", "SHA-384WITHRSAANDMGF1", "SHA384WITHRSA/PSS", "SHA-384WITHRSA/PSS", "SHA512WITHRSAANDMGF1", "SHA-512WITHRSAANDMGF1", "SHA512WITHRSA/PSS", "SHA-512WITHRSA/PSS", "RIPEMD128WITHRSA", "RIPEMD128WITHRSAENCRYPTION", "RIPEMD160WITHRSA", "RIPEMD160WITHRSAENCRYPTION", "RIPEMD256WITHRSA", "RIPEMD256WITHRSAENCRYPTION", "NONEWITHRSA", "RSAWITHNONE", "RAWRSA", "RAWRSAPSS", "NONEWITHRSAPSS", "NONEWITHRSASSA-PSS" };

        /// <summary>
        /// MD2
        /// </summary>
        public class MD2
        {
            /// <summary>
            /// MD2withRSA
            /// </summary>
            public const string MD2WITHRSA = "MD2WITHRSA";

            /// <summary>
            /// MD2withRSA
            /// </summary>
            public const string MD2WITHRSAENCRYPTION = "MD2WITHRSAENCRYPTION";
        }

        /// <summary>
        /// MD4
        /// </summary>
        public class MD4
        {
            /// <summary>
            /// MD4withRSA
            /// </summary>
            public const string MD4WITHRSA = "MD4WITHRSA";

            /// <summary>
            /// MD4withRSA
            /// </summary>
            public const string MD4WITHRSAENCRYPTION = "MD4WITHRSAENCRYPTION";
        }

        /// <summary>
        /// MD5
        /// </summary>
        public class MD5
        {
            /// <summary>
            /// MD5withRSA
            /// </summary>
            public const string MD5WITHRSA = "MD5WITHRSA";

            /// <summary>
            /// MD5withRSA
            /// </summary>
            public const string MD5WITHRSAENCRYPTION = "MD5WITHRSAENCRYPTION";
        }

        /// <summary>
        /// SHA1
        /// </summary>
        public class SHA1
        {
            /// <summary>
            /// SHA-1withRSA
            /// </summary>
            public const string SHA1WITHRSA = "SHA1WITHRSA";

            /// <summary>
            /// SHA-1withRSA
            /// </summary>
            public const string SHA1WITHRSAENCRYPTION = "SHA1WITHRSAENCRYPTION";

            /// <summary>
            /// SHA-1withRSA
            /// </summary>
            public const string SHA_1WITHRSA = "SHA-1WITHRSA";

            /// <summary>
            /// SHA-1withRSAandMGF1
            /// </summary>
            public const string SHA1WITHRSAANDMGF1 = "SHA1WITHRSAANDMGF1";

            /// <summary>
            /// SHA-1withRSAandMGF1
            /// </summary>
            public const string SHA_1WITHRSAANDMGF1 = "SHA-1WITHRSAANDMGF1";

            /// <summary>
            /// SHA-1withRSAandMGF1
            /// </summary>
            public const string SHA1WITHRSA_PSS = "SHA1WITHRSA/PSS";

            /// <summary>
            /// SHA-1withRSAandMGF1
            /// </summary>
            public const string SHA_1WITHRSA_PSS = "SHA-1WITHRSA/PSS";
        }

        /// <summary>
        /// SHA224
        /// </summary>
        public class SHA224
        {
            /// <summary>
            /// SHA-224withRSA
            /// </summary>
            public const string SHA224WITHRSA = "SHA224WITHRSA";

            /// <summary>
            /// SHA-224withRSA
            /// </summary>
            public const string SHA224WITHRSAENCRYPTION = "SHA224WITHRSAENCRYPTION";

            /// <summary>
            /// SHA-224withRSA
            /// </summary>
            public const string SHA_224WITHRSA = "SHA-224WITHRSA";

            /// <summary>
            /// SHA-224withRSAandMGF1
            /// </summary>
            public const string SHA224WITHRSAANDMGF1 = "SHA224WITHRSAANDMGF1";

            /// <summary>
            /// SHA-224withRSAandMGF1
            /// </summary>
            public const string SHA_224WITHRSAANDMGF1 = "SHA-224WITHRSAANDMGF1";

            /// <summary>
            /// SHA-224withRSAandMGF1
            /// </summary>
            public const string SHA224WITHRSA_PSS = "SHA224WITHRSA/PSS";

            /// <summary>
            /// SHA-224withRSAandMGF1
            /// </summary>
            public const string SHA_224WITHRSA_PSS = "SHA-224WITHRSA/PSS";
        }

        /// <summary>
        /// SHA256
        /// </summary>
        public class SHA256
        {
            /// <summary>
            /// SHA-256withRSA
            /// </summary>
            public const string SHA256WITHRSA = "SHA256WITHRSA";

            /// <summary>
            /// SHA-256withRSA
            /// </summary>
            public const string SHA256WITHRSAENCRYPTION = "SHA256WITHRSAENCRYPTION";

            /// <summary>
            /// SHA-256withRSA
            /// </summary>
            public const string SHA_256WITHRSA = "SHA-256WITHRSA";

            /// <summary>
            /// SHA-256withRSAandMGF1
            /// </summary>
            public const string SHA256WITHRSAANDMGF1 = "SHA256WITHRSAANDMGF1";

            /// <summary>
            /// SHA-256withRSAandMGF1
            /// </summary>
            public const string SHA_256WITHRSAANDMGF1 = "SHA-256WITHRSAANDMGF1";

            /// <summary>
            /// SHA-256withRSAandMGF1
            /// </summary>
            public const string SHA256WITHRSA_PSS = "SHA256WITHRSA/PSS";

            /// <summary>
            /// SHA-256withRSAandMGF1
            /// </summary>
            public const string SHA_256WITHRSA_PSS = "SHA-256WITHRSA/PSS";
        }

        /// <summary>
        /// SHA384
        /// </summary>
        public class SHA384
        {
            /// <summary>
            /// SHA-384withRSA
            /// </summary>
            public const string SHA384WITHRSA = "SHA384WITHRSA";

            /// <summary>
            /// SHA-384withRSA
            /// </summary>
            public const string SHA384WITHRSAENCRYPTION = "SHA384WITHRSAENCRYPTION";

            /// <summary>
            /// SHA-384withRSA
            /// </summary>
            public const string SHA_384WITHRSA = "SHA-384WITHRSA";

            /// <summary>
            /// SHA-384withRSAandMGF1
            /// </summary>
            public const string SHA384WITHRSAANDMGF1 = "SHA384WITHRSAANDMGF1";

            /// <summary>
            /// SHA-384withRSAandMGF1
            /// </summary>
            public const string SHA_384WITHRSAANDMGF1 = "SHA-384WITHRSAANDMGF1";

            /// <summary>
            /// SHA-384withRSAandMGF1
            /// </summary>
            public const string SHA384WITHRSA_PSS = "SHA384WITHRSA/PSS";

            /// <summary>
            /// SHA-384withRSAandMGF1
            /// </summary>
            public const string SHA_384WITHRSA_PSS = "SHA-384WITHRSA/PSS";
        }

        /// <summary>
        /// SHA512
        /// </summary>
        public class SHA512
        {
            /// <summary>
            /// SHA-512withRSA
            /// </summary>
            public const string SHA512WITHRSA = "SHA512WITHRSA";

            /// <summary>
            /// SHA-512withRSA
            /// </summary>
            public const string SHA512WITHRSAENCRYPTION = "SHA512WITHRSAENCRYPTION";

            /// <summary>
            /// SHA-512withRSA
            /// </summary>
            public const string SHA_512WITHRSA = "SHA-512WITHRSA";

            /// <summary>
            /// SHA-512withRSAandMGF1
            /// </summary>
            public const string SHA512WITHRSAANDMGF1 = "SHA512WITHRSAANDMGF1";

            /// <summary>
            /// SHA-512withRSAandMGF1
            /// </summary>
            public const string SHA_512WITHRSAANDMGF1 = "SHA-512WITHRSAANDMGF1";

            /// <summary>
            /// SHA-512withRSAandMGF1
            /// </summary>
            public const string SHA512WITHRSA_PSS = "SHA512WITHRSA/PSS";

            /// <summary>
            /// SHA-512withRSAandMGF1
            /// </summary>
            public const string SHA_512WITHRSA_PSS = "SHA-512WITHRSA/PSS";
        }

        /// <summary>
        /// PSS
        /// </summary>
        public class PSS
        {
            /// <summary>
            /// PSSwithRSA
            /// </summary>
            public const string PSSWITHRSA = "PSSWITHRSA";

            /// <summary>
            /// PSSwithRSA
            /// </summary>
            public const string RSASSA_PSS = "RSASSA-PSS";

            /// <summary>
            /// PSSwithRSA
            /// </summary>
            public const string RSAPSS = "RSAPSS";
        }

        /// <summary>
        /// RIPEMD
        /// </summary>
        public class Ripemd
        {
            /// <summary>
            /// RIPEMD128withRSA
            /// </summary>
            public const string RIPEMD128WITHRSA = "RIPEMD128WITHRSA";

            /// <summary>
            /// RIPEMD128withRSA
            /// </summary>
            public const string RIPEMD128WITHRSAENCRYPTION = "RIPEMD128WITHRSAENCRYPTION";

            /// <summary>
            /// RIPEMD160withRSA
            /// </summary>
            public const string RIPEMD160WITHRSA = "RIPEMD160WITHRSA";

            /// <summary>
            /// RIPEMD160withRSA
            /// </summary>
            public const string RIPEMD160WITHRSAENCRYPTION = "RIPEMD160WITHRSAENCRYPTION";

            /// <summary>
            /// RIPEMD256withRSA
            /// </summary>
            public const string RIPEMD256WITHRSA = "RIPEMD256WITHRSA";

            /// <summary>
            /// RIPEMD256withRSA
            /// </summary>
            public const string RIPEMD256WITHRSAENCRYPTION = "RIPEMD256WITHRSAENCRYPTION";
        }

        /// <summary>
        /// RSA
        /// </summary>
        public const string NONEWITHRSA = "NONEWITHRSA";

        /// <summary>
        /// RSA
        /// </summary>
        public const string RSAWITHNONE = "RSAWITHNONE";

        /// <summary>
        /// RSA
        /// </summary>
        public const string RAWRSA = "RAWRSA";

        /// <summary>
        /// RAWRSASSA-PSS
        /// </summary>
        public const string RAWRSAPSS = "RAWRSAPSS";

        /// <summary>
        /// RAWRSASSA-PSS
        /// </summary>
        public const string NONEWITHRSAPSS = "NONEWITHRSAPSS";

        /// <summary>
        /// RAWRSASSA-PSS
        /// </summary>
        public const string NONEWITHRSASSA_PSS = "NONEWITHRSASSA-PSS";
    }

    /// <summary>
    /// 散列算法
    /// </summary>
    public enum HashAlgorithm
    {
        NONE, RAW, MD2, MD4, MD5, SHA1, SHA224, SHA256, SHA384, SHA512, PSS, RIPEMD128, RIPEMD160, RIPEMD256
    }

    /// <summary>
    /// 加密模式
    /// </summary>
    public enum CipherMode { ECB, NONE }

    /// <summary>
    /// 填充算法
    /// </summary>
    public enum CipherPadding
    {
        NOPADDING,
        RAW,
        ISO10126PADDING,
        ISO10126D2PADDING,
        ISO10126_2PADDING,
        ISO7816_4PADDING,
        ISO9797_1PADDING,
        ISO9796_1,
        ISO9796_1PADDING,
        OAEP,
        OAEPPADDING,
        OAEPWITHMD5ANDMGF1PADDING,
        OAEPWITHSHA1ANDMGF1PADDING,
        OAEPWITHSHA_1ANDMGF1PADDING,
        OAEPWITHSHA224ANDMGF1PADDING,
        OAEPWITHSHA_224ANDMGF1PADDING,
        OAEPWITHSHA256ANDMGF1PADDING,
        OAEPWITHSHA_256ANDMGF1PADDING,
        OAEPWITHSHA384ANDMGF1PADDING,
        OAEPWITHSHA_384ANDMGF1PADDING,
        OAEPWITHSHA512ANDMGF1PADDING,
        OAEPWITHSHA_512ANDMGF1PADDING,
        PKCS1,
        PKCS1PADDING,
        PKCS5,
        PKCS5PADDING,
        PKCS7,
        PKCS7PADDING,
        TBCPADDING,
        WITHCTS,
        X923PADDING,
        ZEROBYTEPADDING,
    }
}
