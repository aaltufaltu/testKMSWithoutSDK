using System;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

class KmsUnsignedPayload
{
    private static string accessKey = "<YOUR_ACCESS_KEY>";
    private static string secretKey = "<YOUR_SECRET_KEY>";
    private static string sessionToken = "<YOUR_SESSION_TOKEN>";
    private static string region = "us-east-1";
    private static string keyArn = "<YOUR_KEY_ARN>";

    static void Main()
    {
        Console.WriteLine("=== AWS KMS Manual Encrypt (UNSIGNED-PAYLOAD) ===");
        Console.Write("Enter plaintext to encrypt: ");
        string plaintext = Console.ReadLine();

        Encrypt(plaintext);
    }

    public static void Encrypt(string plaintext)
    {
        SendKmsRequest("Encrypt", plaintext, isPlainText: true);
    }

    public static void Decrypt(string base64Ciphertext)
    {
        SendKmsRequest("Decrypt", base64Ciphertext, isPlainText: false);
    }

    private static void SendKmsRequest(string action, string data, bool isPlainText)
    {
        string service = "kms";
        string host = $"kms.{region}.amazonaws.com";
        string endpoint = $"https://{host}/";

        // Actual JSON payload to send
        string payload = isPlainText
            ? $"{{\"KeyId\":\"{keyArn}\",\"Plaintext\":\"{Convert.ToBase64String(Encoding.UTF8.GetBytes(data))}\"}}"
            : $"{{\"CiphertextBlob\":\"{data}\"}}";

        byte[] payloadBytes = Encoding.UTF8.GetBytes(payload);

        // Dates
        DateTime utcNow = DateTime.UtcNow;
        string amzDate = utcNow.ToString("yyyyMMddTHHmmssZ");
        string dateStamp = utcNow.ToString("yyyyMMdd");

        // Canonical request in UNSIGNED-PAYLOAD mode
        string signedHeaders = "content-type;host;x-amz-date;x-amz-security-token;x-amz-target";

        string canonicalHeaders =
            $"content-type:application/x-amz-json-1.1\n" +
            $"host:{host}\n" +
            $"x-amz-date:{amzDate}\n" +
            $"x-amz-security-token:{sessionToken}\n" +
            $"x-amz-target:TrentService.{action}\n";

        string canonicalRequest =
            "POST\n" +
            "/\n\n" +
            canonicalHeaders + "\n" +
            signedHeaders + "\n" +
            "UNSIGNED-PAYLOAD";

        string canonicalHash = ToHexString(Sha256(Encoding.UTF8.GetBytes(canonicalRequest)));

        // String to sign
        string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
        string stringToSign =
            "AWS4-HMAC-SHA256\n" +
            $"{amzDate}\n" +
            $"{credentialScope}\n" +
            canonicalHash;

        // Signature
        byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
        string signature = ToHexString(HmacSha256(stringToSign, signingKey));

        string authorizationHeader =
            $"AWS4-HMAC-SHA256 Credential={accessKey}/{credentialScope}, SignedHeaders={signedHeaders}, Signature={signature}";

        // Debug output
        Console.WriteLine("\n=== DEBUG ===");
        Console.WriteLine("Payload:\n" + payload);
        Console.WriteLine("\nCanonical Request:\n" + canonicalRequest);
        Console.WriteLine("\nString to Sign:\n" + stringToSign);
        Console.WriteLine("\nAuthorization Header:\n" + authorizationHeader);
        Console.WriteLine("===================\n");

        // Send request
        using (var client = new HttpClient())
        {
            var httpRequest = new HttpRequestMessage(HttpMethod.Post, endpoint);
            httpRequest.Content = new StringContent(payload, Encoding.UTF8, "application/x-amz-json-1.1");

            httpRequest.Headers.TryAddWithoutValidation("Authorization", authorizationHeader);
            httpRequest.Headers.Add("X-Amz-Date", amzDate);
            httpRequest.Headers.Add("X-Amz-Target", $"TrentService.{action}");
            httpRequest.Headers.Add("X-Amz-Security-Token", sessionToken);
            httpRequest.Headers.Add("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD");

            var response = client.SendAsync(httpRequest).Result;
            Console.WriteLine($"Response: {(int)response.StatusCode} {response.ReasonPhrase}");
            Console.WriteLine(response.Content.ReadAsStringAsync().Result);
        }
    }

    // ===================== HELPERS =====================
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
