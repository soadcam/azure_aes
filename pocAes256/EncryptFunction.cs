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
        private const string KEY = "v6K88GdfVAjgMEwV6OxRGKCA6E0sVE4T";

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
            return new OkObjectResult(new { result = responseMessage });
        }

        private static string EncryptRequest(string dataToEncrypt, ILogger log)
        {
            try
            {
                return AesEncrypt(dataToEncrypt, Encoding.UTF8.GetBytes(KEY));
            }
            catch (CryptographicException e)
            {
                log.LogError("A Cryptographic error occurred: {0}", e.ToString());
                return null;
            }
        }

        private static string AesEncrypt(string data, byte[] key)
        {
            return Convert.ToBase64String(AesEncrypt(Encoding.UTF8.GetBytes(data), key));
        }

        private static byte[] AesEncrypt(byte[] data, byte[] key)
        {
            if (data == null || data.Length <= 0)
            {
                throw new ArgumentNullException($"{nameof(data)} cannot be empty");
            }

            using (var aes = new AesCryptoServiceProvider
            {
                Key = key,
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            })
            {
                aes.GenerateIV();
                var iv = aes.IV;
                using (var encrypter = aes.CreateEncryptor(aes.Key, iv))
                using (var cipherStream = new MemoryStream())
                {
                    using (var tCryptoStream = new CryptoStream(cipherStream, encrypter, CryptoStreamMode.Write))
                    using (var tBinaryWriter = new BinaryWriter(tCryptoStream))
                    {
                        cipherStream.Write(iv);
                        tBinaryWriter.Write(data);
                        tCryptoStream.FlushFinalBlock();
                    }
                    var cipherBytes = cipherStream.ToArray();
                    return cipherBytes;
                }
            }
        }
    }
}
