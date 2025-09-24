namespace testKMSWithoutSDK
{
    using System;
    using System.Net.Http;
    using System.Text;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using Newtonsoft.Json;

    class Program
    {
        // 🔑 Replace with your credentials
        private static string accessKey = "<YOUR_ACCESS_KEY>";
        private static string secretKey = "<YOUR_SECRET_KEY>";
        private static string sessionToken = "<YOUR_SESSION_TOKEN>"; // leave empty if not using temporary creds
        private static string region = "us-east-1"; // your region
        private static string keyId = "arn:aws:kms:us-east-1:123456789012:key/xxxx-xxxx"; // your KMS key ARN

        static async Task Main()
        {
            string text = "Hello KMS with x-amz-content-sha256!";
            Console.WriteLine("Plaintext: " + text);

            string ciphertext = await EncryptAsync(text);
            Console.WriteLine("Encrypted (Base64): " + ciphertext);

            string decrypted = await DecryptAsync(ciphertext);
            Console.WriteLine("Decrypted: " + decrypted);
        }

        // 🔹 Encrypt
        public static async Task<string> EncryptAsync(string plainText)
        {
            var payload = new
            {
                KeyId = keyId,
                Plaintext = Convert.ToBase64String(Encoding.UTF8.GetBytes(plainText))
            };

            string response = await SendKmsRequest("TrentService.Encrypt", payload);
            dynamic json = JsonConvert.DeserializeObject(response);
            return json.CiphertextBlob;
        }

        // 🔹 Decrypt
        public static async Task<string> DecryptAsync(string cipherTextBlob)
        {
            var payload = new
            {
                CiphertextBlob = cipherTextBlob
            };

            string response = await SendKmsRequest("TrentService.Decrypt", payload);
            dynamic json = JsonConvert.DeserializeObject(response);

            byte[] plainBytes = Convert.FromBase64String((string)json.Plaintext);
            return Encoding.UTF8.GetString(plainBytes);
        }

        // 🔹 Send signed request
        private static async Task<string> SendKmsRequest(string amzTarget, object payload)
        {
            string requestJson = JsonConvert.SerializeObject(payload);
            var endpoint = $"https://kms.{region}.amazonaws.com/";

            var requestDate = DateTime.UtcNow;
            string amzDate = requestDate.ToString("yyyyMMddTHHmmssZ");
            string dateStamp = requestDate.ToString("yyyyMMdd");

            // ✅ SHA256 hash of body (hex string)
            byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);
            string contentHash = ToHexString(SHA256.Create().ComputeHash(requestBytes));

            // Canonical request
            string canonicalRequest =
                "POST\n" +
                "/\n" +
                "\n" +
                $"content-type:application/x-amz-json-1.1\n" +
                $"host:kms.{region}.amazonaws.com\n" +
                $"x-amz-content-sha256:{contentHash}\n" +
                $"x-amz-date:{amzDate}\n" +
                $"x-amz-target:{amzTarget}\n\n" +
                $"content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target\n" +
                $"{contentHash}";

            string credentialScope = $"{dateStamp}/{region}/kms/aws4_request";
            string stringToSign =
                "AWS4-HMAC-SHA256\n" +
                $"{amzDate}\n" +
                $"{credentialScope}\n" +
                ToHexString(SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(canonicalRequest)));

            // 🔑 Derive signing key
            byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, "kms");
            string signature = ToHexString(HmacSHA256(stringToSign, signingKey));

            // Authorization header
            string authorizationHeader =
                $"AWS4-HMAC-SHA256 Credential={accessKey}/{credentialScope}, " +
                $"SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target, " +
                $"Signature={signature}";

            using (var client = new HttpClient())
            {
                var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint);
                httpRequest.Headers.Add("X-Amz-Date", amzDate);
                httpRequest.Headers.Add("X-Amz-Target", amzTarget);
                httpRequest.Headers.Add("Authorization", authorizationHeader);
                httpRequest.Headers.Add("X-Amz-Content-Sha256", contentHash);

                // ✅ Add Session Token if present
                if (!string.IsNullOrEmpty(sessionToken))
                {
                    httpRequest.Headers.Add("X-Amz-Security-Token", sessionToken);
                }

                httpRequest.Content = new StringContent(requestJson, Encoding.UTF8, "application/x-amz-json-1.1");

                HttpResponseMessage response = await client.SendAsync(httpRequest);
                string responseContent = await response.Content.ReadAsStringAsync();

                if (!response.IsSuccessStatusCode)
                    throw new Exception($"Error {response.StatusCode}: {responseContent}");

                return responseContent;
            }
        }

        // --- Helpers for signing ---
        private static byte[] HmacSHA256(string data, byte[] key)
        {
             var hmac = new HMACSHA256(key);
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
        }

        private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
        {
            byte[] kDate = HmacSHA256(dateStamp, Encoding.UTF8.GetBytes("AWS4" + key));
            byte[] kRegion = HmacSHA256(regionName, kDate);
            byte[] kService = HmacSHA256(serviceName, kRegion);
            byte[] kSigning = HmacSHA256("aws4_request", kService);
            return kSigning;
        }

        private static string ToHexString(byte[] data) =>
            BitConverter.ToString(data).Replace("-", "").ToLower();
    }

}
