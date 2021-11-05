#r "Newtonsoft.Json"

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

private const string KEY = "v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T";
private const string APLHA = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
private const int IV_SIZE = 16;

public static async Task<IActionResult> Run(HttpRequest req, ILogger log)
{
    log.LogInformation("C# start encryption.");

    string queryValue = req.Query["value"];
    string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
    dynamic data = JsonConvert.DeserializeObject(requestBody);
    string plainText = queryValue ?? Convert.ToString(data?.value);
    string iv = GenerateIV();

    string responseMessage = EncryptRequest(plainText, iv, log);
    return new OkObjectResult(new { result = responseMessage, iv });
}

private static string EncryptRequest(string dataToEncrypt, string iv, ILogger log)
{
    try
    {
        byte[] cryptkey = Encoding.UTF8.GetBytes(KEY);
        byte[] initVector = Encoding.UTF8.GetBytes(iv);

        using (var rijndaelManaged =
                new RijndaelManaged { Key = cryptkey, IV = initVector, Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7 })
        using (var memoryStream = new MemoryStream())
        using (var cryptoStream =
                new CryptoStream(memoryStream,
                    rijndaelManaged.CreateEncryptor(cryptkey, initVector),
                    CryptoStreamMode.Write))
        {
            using (var ws = new StreamWriter(cryptoStream))
            {
                ws.Write(dataToEncrypt);
            }
            return Convert.ToBase64String(memoryStream.ToArray());
        }
    }
    catch (CryptographicException e)
    {
        log.LogError("A Cryptographic error occurred: {0}", e.ToString());
        return null;
    }
}

private static string GenerateIV()
{
    Random random = new Random();
    string iv = new string(Enumerable.Repeat(APLHA, IV_SIZE)
        .Select(s => s[random.Next(s.Length)]).ToArray());
    return iv;
}
