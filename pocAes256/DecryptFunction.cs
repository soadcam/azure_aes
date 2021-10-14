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
        private const string KEY = "v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T";
        
        private const int IV_SIZE = 16;

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
                byte[] encryptedData = Convert.FromBase64String(dataToDecrypt);
                var initVector = new byte[IV_SIZE];
                Array.Copy(encryptedData, 0, initVector, 0, initVector.Length);
                byte[] cryptkey = Encoding.UTF8.GetBytes(KEY);

                // diff
                int lengthData = encryptedData.Length - initVector.Length;
                byte[] inputData = new byte[lengthData];
                Array.Copy(encryptedData, initVector.Length, inputData, 0, inputData.Length);

                using (var rijndaelManaged =
                       new RijndaelManaged { Mode = CipherMode.CBC, Padding = PaddingMode.PKCS7})
                using (var memoryStream =
                       new MemoryStream(inputData))
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