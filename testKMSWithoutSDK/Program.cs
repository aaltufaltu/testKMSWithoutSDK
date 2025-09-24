using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

class KmsRequestSigner
{
    private static string accessKey = "<YOUR_ACCESS_KEY>";
    private static string secretKey = "<YOUR_SECRET_KEY>";
    private static string sessionToken = "<YOUR_SESSION_TOKEN>"; // optional
    private static string region = "us-east-1";

    public static void Encrypt()
    {
        string service = "kms";
        string host = $"kms.{region}.amazonaws.com";
        string endpoint = $"https://{host}/";

        // JSON body for Encrypt
        string requestJson = "{\"KeyId\":\"<YOUR_KEY_ARN>\",\"Plaintext\":\"SGVsbG8=\"}";
        byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);

        // Step 1: Dates
        DateTime utcNow = DateTime.UtcNow;
        string amzDate = utcNow.ToString("yyyyMMddTHHmmssZ");
        string dateStamp = utcNow.ToString("yyyyMMdd");

        // Step 2: Hash body
        string contentHash = ToHexString(Sha256(requestBytes));

        // Step 3: Canonical request
        string method = "POST";
        string canonicalUri = "/";
        string canonicalQuery = "";
        string canonicalHeaders =
            $"content-type:application/x-amz-json-1.1\n" +
            $"host:{host}\n" +
            $"x-amz-content-sha256:{contentHash}\n" +
            $"x-amz-date:{amzDate}\n" +
            $"x-amz-target:TrentService.Encrypt\n";
        string signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target";

        string canonicalRequest =
            $"{method}\n{canonicalUri}\n{canonicalQuery}\n" +
            $"{canonicalHeaders}\n" +
            $"{signedHeaders}\n" +
            $"{contentHash}";

        string canonicalHash = ToHexString(Sha256(Encoding.UTF8.GetBytes(canonicalRequest)));

        // Step 4: String to sign
        string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
        string stringToSign =
            "AWS4-HMAC-SHA256\n" +
            $"{amzDate}\n" +
            $"{credentialScope}\n" +
            $"{canonicalHash}";

        // Step 5: Derive signing key
        byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, service);

        // Step 6: Signature
        string signature = ToHexString(HmacSha256(stringToSign, signingKey));

        // Step 7: Authorization header
        string authorizationHeader =
            $"AWS4-HMAC-SHA256 Credential={accessKey}/{credentialScope}, " +
            $"SignedHeaders={signedHeaders}, Signature={signature}";

        // ✅ Debug prints
        Console.WriteLine("=== DEBUG ===");
        Console.WriteLine("Canonical Request:\n" + canonicalRequest);
        Console.WriteLine("\nString To Sign:\n" + stringToSign);
        Console.WriteLine("\nSignature:\n" + signature);
        Console.WriteLine("================\n");

        // Step 8: Send request
        using (var client = new HttpClient())
        {
            var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint);
            httpRequest.Content = new StringContent(requestJson, Encoding.UTF8, "application/x-amz-json-1.1");

            httpRequest.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
            httpRequest.Headers.Add("X-Amz-Date", amzDate);
            httpRequest.Headers.Add("X-Amz-Target", "TrentService.Encrypt");
            httpRequest.Headers.Add("X-Amz-Content-Sha256", contentHash);
            if (!string.IsNullOrEmpty(sessionToken))
                httpRequest.Headers.Add("X-Amz-Security-Token", sessionToken);

            var response = client.SendAsync(httpRequest).Result;
            Console.WriteLine($"Response: {(int)response.StatusCode} {response.ReasonPhrase}");
            Console.WriteLine(response.Content.ReadAsStringAsync().Result);
        }
    }

    // === Helpers ===
    private static byte[] Sha256(byte[] data)
    {
        using (var sha256 = SHA256.Create())
            return sha256.ComputeHash(data);
    }

    private static byte[] HmacSha256(string data, byte[] key)
    {
        using (var hmac = new HMACSHA256(key))
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }

    private static string ToHexString(byte[] bytes)
    {
        var sb = new StringBuilder();
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
    {
        byte[] kDate = HmacSha256(dateStamp, Encoding.UTF8.GetBytes("AWS4" + key));
        byte[] kRegion = HmacSha256(regionName, kDate);
        byte[] kService = HmacSha256(serviceName, kRegion);
        byte[] kSigning = HmacSha256("aws4_request", kService);
        return kSigning;
    }

    private static byte[] HmacSha256(string data, byte[] key)
    {
        using (var hmac = new HMACSHA256(key))
            return hmac.ComputeHash(Encoding.UTF8.GetBytes(data));
    }
}
