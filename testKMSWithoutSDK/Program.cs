using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

class KmsSigV4Debugger
{
    private static string accessKey = "<YOUR_ACCESS_KEY>";
    private static string secretKey = "<YOUR_SECRET_KEY>";
    private static string sessionToken = "<YOUR_SESSION_TOKEN>"; // optional
    private static string region = "us-east-1";
    private static string keyArn = "<YOUR_KEY_ARN>";

    public static void DebugEncryptRequest(string plaintext)
    {
        string service = "kms";
        string host = $"kms.{region}.amazonaws.com";
        string endpoint = $"https://{host}/";

        // Body as JSON
        string base64Text = Convert.ToBase64String(Encoding.UTF8.GetBytes(plaintext));
        string requestJson = $"{{\"KeyId\":\"{keyArn}\",\"Plaintext\":\"{base64Text}\"}}";
        byte[] requestBytes = Encoding.UTF8.GetBytes(requestJson);

        // Dates
        DateTime utcNow = DateTime.UtcNow;
        string amzDate = utcNow.ToString("yyyyMMddTHHmmssZ");
        string dateStamp = utcNow.ToString("yyyyMMdd");

        // Body hash
        string contentHash = ToHexString(Sha256(requestBytes));

        // Canonical request
        string signedHeaders = "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-target";
        string canonicalRequest =
            "POST\n" +
            "/\n\n" +
            $"content-type:application/x-amz-json-1.1\n" +
            $"host:{host}\n" +
            $"x-amz-content-sha256:{contentHash}\n" +
            $"x-amz-date:{amzDate}\n" +
            $"x-amz-target:TrentService.Encrypt\n\n" +
            $"{signedHeaders}\n" +
            $"{contentHash}";

        string canonicalHash = ToHexString(Sha256(Encoding.UTF8.GetBytes(canonicalRequest)));

        // String to sign
        string credentialScope = $"{dateStamp}/{region}/{service}/aws4_request";
        string stringToSign =
            "AWS4-HMAC-SHA256\n" +
            $"{amzDate}\n" +
            $"{credentialScope}\n" +
            $"{canonicalHash}";

        // Signature
        byte[] signingKey = GetSignatureKey(secretKey, dateStamp, region, service);
        string signature = ToHexString(HmacSha256(stringToSign, signingKey));

        // Authorization header
        string authorizationHeader =
            $"AWS4-HMAC-SHA256 Credential={accessKey}/{credentialScope}, " +
            $"SignedHeaders={signedHeaders}, Signature={signature}";

        // === Print debug information ===
        Console.WriteLine("=== C# Debug Output ===\n");
        Console.WriteLine("Local UTC time: " + utcNow.ToString("O"));
        Console.WriteLine("Request JSON: " + requestJson + "\n");
        Console.WriteLine("Canonical Request:\n" + canonicalRequest + "\n");
        Console.WriteLine("String to Sign:\n" + stringToSign + "\n");
        Console.WriteLine("Signature:\n" + signature + "\n");
        Console.WriteLine("Authorization Header:\n" + authorizationHeader + "\n");
        Console.WriteLine("====================\n");

        // Optional: Send request to AWS
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

            if (response.Headers.Date.HasValue)
            {
                Console.WriteLine($"AWS server UTC time: {response.Headers.Date.Value.UtcDateTime:O}");
            }
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


//echo|set /p="Hello KMS" > C:\Temp\plaintext.txt
//aws kms encrypt --key-id <YOUR_KEY_ARN> --plaintext fileb://C:\Temp\plaintext.txt --region us-east-1 --debug


//# Create a temporary plaintext file
//$plainTextFile = "C:\Temp\plaintext.txt"
//Set - Content - Path $plainTextFile - Value "Hello KMS" - NoNewline

//# Run AWS CLI encrypt with debug
//aws kms encrypt `
//  --key-id <YOUR_KEY_ARN> `
//  --plaintext fileb://C:\Temp\plaintext.txt `
//  --region us - east - 1 `
//  --debug