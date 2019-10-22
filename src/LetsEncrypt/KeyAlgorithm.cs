namespace McMaster.AspNetCore.LetsEncrypt
{
    /// <summary>
    /// The supported algorithms.
    /// </summary>
    public enum KeyAlgorithm
    {
        /// <summary>
        /// RSASSA-PKCS1-v1_5 using SHA-256.
        /// </summary>
        RS256 = 0,

        /// <summary>
        /// ECDSA using P-256 and SHA-256.
        /// </summary>
        ES256 = 1,

        /// <summary>
        /// ECDSA using P-384 and SHA-384.
        /// </summary>
        ES384 = 2,

        /// <summary>
        /// ECDSA using P-521 and SHA-512.
        /// </summary>
        ES512 = 3
    }
}
