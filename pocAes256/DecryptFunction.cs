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
    public static class DecryptFunction
    {
        [FunctionName("Decryption")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# start encryption.");

            string queryValue = req.Query["value"];
            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            string plainText = queryValue ?? Convert.ToString(data?.value);

            string responseMessage = DecryptRequest(plainText, log);
            return new OkObjectResult(new { encrypted = responseMessage });
        }

        private static string DecryptRequest(string dataToDecrypt, ILogger log)
        {
            try
            {
                byte[] cryptkey = Encoding.UTF8.GetBytes("v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T");
                byte[] initVector = Encoding.UTF8.GetBytes("WAbIiaaGqigzD4Zt");

                using (var rijndaelManaged =
                       new RijndaelManaged { Key = cryptkey, IV = initVector, Mode = CipherMode.CBC })
                using (var memoryStream =
                       new MemoryStream(Convert.FromBase64String(dataToDecrypt)))
                using (var cryptoStream =
                       new CryptoStream(memoryStream,
                           rijndaelManaged.CreateDecryptor(cryptkey, initVector),
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
    }
}
