
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Configuration;
using Azure.Extensions.AspNetCore.Configuration.Secrets;
using System.Security.Cryptography.X509Certificates;
using System.Net;
using Azure.Security.KeyVault.Keys;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Azure;

namespace AzureKeyVault
{
    public class Program
    {
        private static X509Certificate2 Get509Certificate2(string thumbprint)
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            try
            {
                store.Open(OpenFlags.ReadOnly);
                var certificate = store.Certificates
                    .Find(X509FindType.FindByThumbprint, thumbprint, false);

                if(certificate.Count == 0 )
                {
                    throw new Exception("certificate is invalide");
                }

                return certificate[0];
            }
            finally
            {
                store.Close();
            }
        }

        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Configure Azure Key Vault and read the secret key value using Client Secret Key
            var keyVaultURL = builder.Configuration["KeyVaultSecretConfiguration:KeyVaultURL"];
            var keyVaultClientId = builder.Configuration["KeyVaultSecretConfiguration:ClientId"];
            var keyVaultClientSecret = builder.Configuration["KeyVaultSecretConfiguration:ClientSecret"];
            var keyVaultTenantId = builder.Configuration["KeyVaultSecretConfiguration:TenantId"];

            var credential = new ClientSecretCredential(keyVaultTenantId, keyVaultClientId, keyVaultClientSecret);

            var client = new SecretClient(new Uri(keyVaultURL!), credential);
            builder.Configuration.AddAzureKeyVault(client, new AzureKeyVaultConfigurationOptions() { Manager = new PrefixKeyManager("AzureBlob") });

           

            /// Configure Azure Key Vault and read the secret key value using Certificate install in Device
            var keyVaultURLCert = builder.Configuration["KeyVaultSecretConfigurationForCertificate:KeyVaultURL"];
            var keyVaultClientIdCert = builder.Configuration["KeyVaultSecretConfigurationForCertificate:ClientId"];
            var keyVaultThumbPrint = builder.Configuration["KeyVaultSecretConfigurationForCertificate:ThumbPrint"];
            builder.Configuration.AddAzureKeyVault(keyVaultURLCert, keyVaultClientIdCert, Get509Certificate2(keyVaultThumbPrint),new PrefixKeyVaultManager("AzureBlob"));


            // Another way to Configure the Key Vault and use as a DI as service and use to set, get, delete key secret 
            // Ex : '/set-secret' , '/delete-secret
            builder.Services.AddAzureClients(option =>
            {
                option.AddClient<SecretClient, SecretClientOptions>((con, _, _) =>
                {
                    return new SecretClient(new Uri(keyVaultURL!), new ClientSecretCredential(keyVaultTenantId, keyVaultClientId, keyVaultClientSecret));
                });
            });

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();


            // Read The Key Vault Secret's using Client Secret Key
            app.MapGet("/key-vault-secret", (IConfiguration configuration) =>
            {
                return Results.Ok(configuration["ConnectionStrings:AzureBlobStorage"]);
            });



            // Read The Key Vault Secret's using Certificate install in User Device then it not required Client Secret Key
            app.MapGet("/key-vault-secret-using-certificate", (IConfiguration configuration) =>
            {
                return Results.Ok(configuration["ConnectionStrings:AzureBlobStorage"]);
            });


            // Set Secret From Here 
            app.MapGet("/set-secret", async (string key,string value,[FromServices]SecretClient secret) =>
            {
                var secretValue = await secret.SetSecretAsync(key,value);
                return Results.Ok(secretValue);
            });

            // Delete Secret From Here
            app.MapGet("/delete-secret", async (string key, string value, [FromServices] SecretClient secret) =>
            {
                var deleteOperation = await secret.StartDeleteSecretAsync(key);
                while (!deleteOperation.HasCompleted)
                {
                    Thread.Sleep(500);
                    deleteOperation.UpdateStatus();
                }
                return Results.Ok("Deleted");
            });
            

            app.Run();
        }
    }
}