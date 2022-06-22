using Microsoft.IdentityModel.Tokens;
using System;
using System.Security.Cryptography;

namespace JWTWithRS256
{
    internal class Program
    {
        static void Main(string[] args)
        {

            var JWSWithRS256 = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJ1RXJacF9SUjJsRVRiN205a2tmMTJOel8wWjJiaVAyVVZBSDNiRTRfNG5VIn0.eyJleHAiOjE2NTU5MTU2MzMsImlhdCI6MTY1NTkxNTMzMywianRpIjoiODMzYWYwZmItODc1NC00OTBlLTg1MDctMTRlMjY5ZTliNjViIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy9NeVJlYWxtIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjFlZjNlMDJiLTU1MDMtNGJiMC1iNzQ4LTczODRmZDNhMTk3NSIsInR5cCI6IkJlYXJlciIsImF6cCI6Ik15QXBwIiwic2Vzc2lvbl9zdGF0ZSI6Ijc0NWI1Mjc5LTU2ZjctNDM3NC1hYmY1LTIyNzE1ZjM1ZTdlNyIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiaHR0cDovLzEwLjcuNy4xMTozMDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJkZWZhdWx0LXJvbGVzLW15cmVhbG0iLCJvZmZsaW5lX2FjY2VzcyIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiTXlBcHAiOnsicm9sZXMiOlsiQWRtaW4iXX0sImFjY291bnQiOnsicm9sZXMiOlsibWFuYWdlLWFjY291bnQiLCJtYW5hZ2UtYWNjb3VudC1saW5rcyIsInZpZXctcHJvZmlsZSJdfX0sInNjb3BlIjoiZW1haWwgcHJvZmlsZSIsInNpZCI6Ijc0NWI1Mjc5LTU2ZjctNDM3NC1hYmY1LTIyNzE1ZjM1ZTdlNyIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwicHJlZmVycmVkX3VzZXJuYW1lIjoibmljb2xhcyJ9.CPsbaDaaQAkekeyPeEHy3d3ZH0b_CQoXmQUo-gZvTaW25XlUVvIGnM65YYLjC3Ox0OScsr4XDxveZOu6yG_CNqF5ik6JVaUFnlzi6tF1BL3wVv4CikQGJSQHcyqMuRsMN4ThGo4g1peagJsfNWQ8SFfgwoTKh7HETOARHgKMiBAD1lEoFR8oL_WG1tzwbe6W7tBk34F8YcTpknbtJaxilMuOaa5zpEw2SwWao7n1260kwnE_5cFQ0fcn813lS8Kg_naKuraqQXJjMaqLjTr3lMmtoMpDiQyUi6uG8IjMxp9NARMU23Axe8oWnk50dI__LgtNb5x5VYLScoLTZsoA7Q";

            var publicKeyBase64UrlEncoded = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi6G5wRCfqjXJFBhvK+UwAUFU9LDcT3aet0gGZk8hMMPfF5SEBaPqTDuLMh85VXtm0I0KBpUtlgNzMqcmWVoSFTNSSJnmBBmD/26xcidu/wuo4m3wTIca2kOLBtMP/3sjIDOXAQYaCOXjbbDbNB1S49VD6wUyJy8gGwiTsDzuZcNsS5c+hnAiI+WHqUnSll/EGZcKp1Yv7BZH9fYRXdTGYRGcH6ZRH8Nhl9w6QL+gSRA2wZLjS9r5NdZ5Ey8iSezs1Htdtg2sj0mA1QlvdOkPQVzD5hW80it5sHMY0l1W1XJSPnkdGNaTJXyn5Fto15uJhj5nE6MwkwiTfGlwxmZQLwIDAQAB";

            Console.WriteLine($"JWT valid ? {IsJWTValidFromRS256(JWSWithRS256, publicKeyBase64UrlEncoded)}");

        }

        /// <summary>
        /// To validate the content of the JWT with the signature.
        /// The signature is creating by the RSA encoding of the SHA-256 hash of the content of headerBase64UrlEncoded.payloadBase64UrlEncoded 
        /// </summary>
        /// <param name="JWSWithRS256">JWS content of headerBase64UrlEncoded.payloadBase64UrlEncoded.signatureBaseURlEncoded</param>
        /// <param name="publicKeyRSABase64UrlEncoded">publickey of RSA base64 url encoded which will be used to validate the SHA-256 hash from the signature</param>
        /// <returns>True if JWS has header and payload valid with the signature</returns>
        private static bool IsJWTValidFromRS256(string JWSWithRS256, string publicKeyRSABase64UrlEncoded)
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