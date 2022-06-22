using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace JWTWithRS256
{
    public static class JWSWithRS256
    {
        /// <summary>
        /// To validate the content of the JWT with the signature.
        /// The signature is creating by the RSA encoding of the SHA-256 hash of the content of headerBase64UrlEncoded.payloadBase64UrlEncoded 
        /// </summary>
        /// <param name="JWSWithRS256">JWS content of headerBase64UrlEncoded.payloadBase64UrlEncoded.signatureBaseURlEncoded</param>
        /// <param name="publicKeyRSABase64UrlEncoded">publickey of RSA base64 url encoded which will be used to validate the SHA-256 hash from the signature</param>
        /// <returns>True if JWS has header and payload valid with the signature</returns>
        public static bool IsJWTValidFromRS256(string JWSWithRS256, string publicKeyRSABase64UrlEncoded)
        {
            try
            {
                #region === Step 1: Separate the 3 JWS part ===

                var JWSParts = JWSWithRS256.Split('.');

                var headerBase64UrlEncoded = JWSParts[0];
                var payloadBase64UrlEncoded = JWSParts[1];
                var signatureBase64UrlEncoded = JWSParts[2];

                #endregion

                #region === Step 2: Get SHA256HashToBeSigned from {headerBase64UrlEncoded.payloadBase64UrlEncoded} ===

                var SHA256HashToBeSigned = BuildJWTHeaderPayloadSHA256Hash(headerBase64UrlEncoded, payloadBase64UrlEncoded);

                #endregion

                #region === Step 3: Decode the signature from Base64Url into the signature byte[] array ===

                var signatureInBytes = Base64UrlEncoder.DecodeBytes(signatureBase64UrlEncoded);

                #endregion

                #region === Step 4: Build RSA from the public key extracted from the SubjectPublickKeyInfo ===

                using RSACryptoServiceProvider rsaCryptoServiceProvider = new RSACryptoServiceProvider(2048);

                var publicKey = Base64UrlEncoder.DecodeBytes(publicKeyRSABase64UrlEncoded);

                rsaCryptoServiceProvider.ImportSubjectPublicKeyInfo(
                    source: publicKey,
                    bytesRead: out _
                );

                #endregion

                #region === Step 5: Verification that the SHA-256 hash made from the JWS header and payload to be signed matches the one from the Signature ===

                var SHA256ObjectIdentifier = CryptoConfig.MapNameToOID("SHA256");

                return rsaCryptoServiceProvider.VerifyHash(SHA256HashToBeSigned, SHA256ObjectIdentifier, signatureInBytes);

                #endregion
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return false;
            }
        }

        /// <summary>
        /// Build the SHA-256 Hash from the JWs Header and payload which was used to be signed in the JWS.
        /// This Hash will be used to check if it maches the Hash from the signature made from SHA-256 and RSA encoding with the privatekey
        /// The method will do: SHA-256(headerBase64UrlEncoded + . + payloadBase64UrlEncoded)
        /// </summary>
        /// <param name="headerBase64UrlEncoded">JWS Header base64 url encoded</param>
        /// <param name="payloadBase64UrlEncoded">JWS Payload base64 url encoded</param>
        /// <returns></returns>
        private static byte[] BuildJWTHeaderPayloadSHA256Hash(string headerBase64UrlEncoded, string payloadBase64UrlEncoded)
        {
            return SHA256.Create().ComputeHash(
               System.Text.Encoding.UTF8.GetBytes($"{headerBase64UrlEncoded}.{payloadBase64UrlEncoded}"));
        }
    }
}
