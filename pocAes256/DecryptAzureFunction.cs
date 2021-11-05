#r "Newtonsoft.Json"

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

private const string KEY = "v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T";
private const int IV_SIZE = 16;

public static async Task<IActionResult> Run(HttpRequest req, ILogger log)
{
    log.LogInformation("C# start encryption.");

    string queryValue = req.Query["value"];
    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
    dynamic data = JsonConvert.DeserializeObject(requestBody);
    string plainText = queryValue ?? Convert.ToString(data?.value);

    string responseMessage = DecryptRequest(plainText, log);
    return new OkObjectResult(new { result = JsonConvert.DeserializeObject(responseMessage) });
}

private static string DecryptRequest(string dataToDecrypt, ILogger log)
{
    try
    {
        byte[] cryptkey = Encoding.UTF8.GetBytes(KEY);
        string ivRaw = dataToDecrypt.Substring(0, IV_SIZE);
        string inputRaw = dataToDecrypt.Substring(IV_SIZE);
        byte[] ivData = Encoding.UTF8.GetBytes(ivRaw);
        byte[] inputData = Convert.FromBase64String(inputRaw);

        using (var rijndaelManaged =
                new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
        using (var memoryStream =
                new MemoryStream(inputData))
        using (var cryptoStream =
                new CryptoStream(memoryStream,
                    rijndaelManaged.CreateDecryptor(cryptkey, ivData),
                    CryptoStreamMode.Read))
        {
            return new StreamReader(cryptoStream).ReadToEnd();
        }
    }
    catch (CryptographicException e)
    {
        log.LogError("A Cryptographic error occurred: {0}", e.ToString());
        return null;
    }
}
