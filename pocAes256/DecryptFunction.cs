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
            return new OkObjectResult(new { result = responseMessage });
        }

        private static string DecryptRequest(string dataToDecrypt, ILogger log)
        {
            try
            {
                return AesDecrypt(dataToDecrypt, Encoding.UTF8.GetBytes(KEY));
            }
            catch (CryptographicException e)
            {
                log.LogError("A Cryptographic error occurred: {0}", e.ToString());
                return null;
            }
        }

        private static string AesDecrypt(string data, byte[] key)
        {
            return Encoding.UTF8.GetString(AesDecrypt(Convert.FromBase64String(data), key));
        }

        private static byte[] AesDecrypt(byte[] data, byte[] key)
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
                var iv = new byte[16];
                Array.Copy(data, 0, iv, 0, iv.Length);
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, aes.CreateDecryptor(aes.Key, iv), CryptoStreamMode.Write))
                    using (var binaryWriter = new BinaryWriter(cs))
                    {
                        binaryWriter.Write(
                            data,
                            iv.Length,
                            data.Length - iv.Length
                        );
                    }

                    var dataBytes = ms.ToArray();

                    return dataBytes;
                }
            }
        }
    }
}
