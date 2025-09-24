using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

class KmsCanopyStyle
{
    private static string accessKey = "<YOUR_ACCESS_KEY>";
    private static string secretKey = "<YOUR_SECRET_KEY>";
    private static string sessionToken = "<YOUR_SESSION_TOKEN>"; // required for temp creds
    private static string region = "us-east-1";
    private static string keyArn = "<YOUR_KEY_ARN>";

    public static void Encrypt(string plaintext)
    {
        string service = "kms";
        string host = $"kms.{region}.amazonaws.com";
        string endpoint = $"https://{host}/";

        // Body as JSON
        string base64Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        string requestJson = $"{{\"KeyId\":\"{keyArn}\",\"Plaintext\":\"{base64Text}\"}}";

        // Dates
        DateTime utcNow = DateTime.UtcNow;
        string amzDate = utcNow.ToString("yyyyMMddTHHmmssZ");
        string dateStamp = utcNow.ToString("yyyyMMdd");

        // === Canonical request (Canopy style) ===
        string signedHeaders = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

        string canonicalHeaders =
            $"content-type:application/x-amz-json-1.1\n" +
            $"host:{host}\n" +
            $"x-amz-date:{amzDate}\n" +
            $"x-amz-security-token:{sessionToken}\n" +
            $"x-amz-target:TrentService.Encrypt\n";

        string canonicalRequest =
            "POST\n" +
            "/\n\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            ToHexString(Sha256(Encoding.UTF8.GetBytes(requestJson))); // hash of payload

        string canonicalHash = ToHexString(Sha256(Encoding.UTF8.GetBytes(canonicalRequest)));

        // === String to sign ===
        string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
        string stringToSign =
            "AWS4-HMAC-SHA256\n" +
            $"{amzDate}\n" +
            $"{credentialScope}\n" +
            canonicalHash;

        // === Signature ===
        byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
        string signature = ToHexString(HmacSha256(stringToSign, signingKey));

        string authorizationHeader =
            $"AWS4-HMAC-SHA256 Credential={accessKey}/{credentialScope}, " +
            $"SignedHeaders={signedHeaders}, Signature={signature}";

        // === Debug output ===
        Console.WriteLine("=== DEBUG ===");
        Console.WriteLine("Canonical Request:\n" + canonicalRequest);
        Console.WriteLine("\nString to Sign:\n" + stringToSign);
        Console.WriteLine("\nAuthorization Header:\n" + authorizationHeader);
        Console.WriteLine("================\n");

        // === Send request ===
        using (var client = new HttpClient())
        {
            var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint);
            httpRequest.Content = new StringContent(requestJson, Encoding.UTF8, "application/x-amz-json-1.1");

            httpRequest.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
            httpRequest.Headers.Add("X-Amz-Date", amzDate);
            httpRequest.Headers.Add("X-Amz-Target", "TrentService.Encrypt");
            httpRequest.Headers.Add("X-Amz-Security-Token", sessionToken);

            var response = client.SendAsync(httpRequest).Result;
            Console.WriteLine($"Response: {(int)response.StatusCode} {response.ReasonPhrase}");
            Console.WriteLine(response.Content.ReadAsStringAsync().Result);

            if (response.Headers.Date.HasValue)
                Console.WriteLine($"AWS server UTC time: {response.Headers.Date.Value.UtcDateTime:O}");
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

    private static byte[] GetSignatureKey(string key, string dateStamp, string regionName, string serviceName)
    {
        byte[] kDate = HmacSha256(dateStamp, Encoding.UTF8.GetBytes("AWS4" + key));
        byte[] kRegion = HmacSha256(regionName, kDate);
        byte[] kService = HmacSha256(serviceName, kRegion);
        return HmacSha256("aws4_request", kService);
    }

    private static string ToHexString(byte[] bytes)
    {
        var sb = new StringBuilder();
        foreach (var b in bytes) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }
}
