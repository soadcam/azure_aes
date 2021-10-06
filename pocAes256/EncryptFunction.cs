using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace pocAes256
{
    public static class EncryptFunction
    {
        [FunctionName("Encryption")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# start encryption.");

            string queryValue = req.Query["value"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            string plainText = queryValue ?? Convert.ToString(data?.value);
            
            string responseMessage = EncryptRequest(plainText, log);
            return new OkObjectResult(new { encrypted = responseMessage });
        }

        private static string EncryptRequest(string dataToEncrypt, ILogger log)
        {
            try
            {
                byte[] cryptkey = Encoding.UTF8.GetBytes("v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T");
                byte[] initVector = Encoding.UTF8.GetBytes("WAbIiaaGqigzD4Zt");

                using (var rijndaelManaged =
                       new RijndaelManaged { Key = cryptkey, IV = initVector, Mode = CipherMode.CBC })
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
    }
}
