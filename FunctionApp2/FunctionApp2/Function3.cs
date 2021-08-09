using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Text;
using System.Buffers.Text;
using Microsoft.IdentityModel.Tokens;
using Azure.Security.KeyVault.Certificates;
using Azure.Identity;
using System.Security.Cryptography;

namespace FunctionApp2
{
    public static class Function3
    {
        [FunctionName("Function3")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Function, "get", "post", Route = null)] HttpRequest req,
            ILogger log)
        {
            log.LogInformation("C# HTTP trigger function processed a request.");

            string name = req.Query["name"];

            string requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            dynamic data = JsonConvert.DeserializeObject(requestBody);
            name = name ?? data?.name;

            string responseMessage = string.IsNullOrEmpty(name)
                ? "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response."
                : $"Hello, {name}. This HTTP triggered function executed successfully.";


            string header = "{\"alg\":\"RS256\"}";
            string claimTemplate = "'{'\"iss\": \"{0}\", \"sub\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\", \"jti\": \"{4\"'}'";

            try
            {
                StringBuilder token = new StringBuilder();

                //Encode the JWT Header and add it to our string to sign
                token.Append(Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(header)));
                //Separate with a period
                token.Append(".");

                string payload = await GetCliams(claimTemplate);
                //Add the encoded claims object
                token.Append(Base64UrlEncoder.Encode(Encoding.UTF8.GetBytes(payload)));

                string signedPayload = await Sign(token);
                //Separate with a period
                token.Append(".");
                //Add the encoded signature
                token.Append(signedPayload);

                Console.WriteLine(token.ToString());

            }
            catch (Exception e)
            {
                Console.WriteLine(e.StackTrace);
            }



            return new OkObjectResult(responseMessage);
        }

        private static async  Task<string> GetCliams(string claimTemplate)
        {
            //Create the JWT Claims Object
            String[] claimArray = new String[4];
            claimArray[0] = "3MVG9_I_oWkIqLrknB6cXCr7k5QFC0sqHONZzzVmMqB8yUYcdFVgtp_tql7VRP1v_HJB_sgNgYZ3ZnywKJRhb";
            claimArray[1] = "vappana@wish.org.dev ";
            claimArray[2] = "https://test.salesforce.com";
            claimArray[3] = (((DateTime.Now.Ticks / TimeSpan.TicksPerMillisecond) / 1000) + 300).ToString();
            claimArray[4] = "<JTI>";
            string payload = string.Format(claimTemplate, claimArray);
            return payload;
        }

        private static async Task<string> Sign(StringBuilder token)
        {
            //Load the private key from a keystore
            const string certificateName = "myCertificate";
            var keyVaultName = Environment.GetEnvironmentVariable("KEY_VAULT_NAME");
            var kvUri = $"https://{keyVaultName}.vault.azure.net";

            var client = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());

            Console.WriteLine($"Retrieving your certificate from {keyVaultName}.");
            var cert2 = await client.DownloadCertificateAsync(certificateName);
            var x509 = cert2.Value;
            var provider = (RSACryptoServiceProvider)x509.PrivateKey;
            Console.WriteLine($"Your certificate version is '{cert2.Value.Version}'.");

            var signedBytes = provider.SignData(Encoding.UTF8.GetBytes(token.ToString()), new SHA256CryptoServiceProvider());
            string signedPayload = Base64UrlEncoder.Encode(signedBytes);
            return signedPayload;
        }

        private static async Task<byte[]> SignUsingPrivateKey(StringBuilder token)
        {
            const string certificateName = "myCertificate";
            var keyVaultName = Environment.GetEnvironmentVariable("KEY_VAULT_NAME");
            var kvUri = $"https://{keyVaultName}.vault.azure.net";

            var client = new CertificateClient(new Uri(kvUri), new DefaultAzureCredential());

            Console.WriteLine($"Retrieving your certificate from {keyVaultName}.");
            var certificate = await client.GetCertificateAsync(certificateName);
            var cert2 = await client.DownloadCertificateAsync(certificateName);
            var x509 = cert2.Value;
            var provider = (RSACryptoServiceProvider)x509.PrivateKey;
            Console.WriteLine($"Your certificate version is '{certificate.Value.Properties.Version}'.");

            return provider.SignData(Encoding.UTF8.GetBytes(token.ToString()), new SHA256CryptoServiceProvider());
        }

        //private static async byte[] m2()
        //{
        //    RSACryptoServiceProvider key = new RSACryptoServiceProvider();
        //    key.FromXmlString(privateCert.PrivateKey.ToXmlString(true));
        //    // Once that is done we can now sign a piece of data as follows:

        //    //Create some data to sign
        //    byte[] data = new byte[1024];

        //    //Sign the data
        //    byte[] sig = key.SignData(data, CryptoConfig.MapNameToOID("SHA256"));


        //    return sig;
        //}
    }
}
