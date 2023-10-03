

![cbimage (1)](https://github.com/jil1710/readmedemo/assets/125335932/3579fb6c-c211-4e8a-8bc2-3f1276cc8ec8)

# Azure Key Vault

- Azure Key Vault is a cloud-based, secure storage solution that safeguards your application’s secrets or other sensitive data pertaining to your application. Such secrets might be tokens, keys, IDs, passwords, certificates, etc. Azure Key Vault provides a safe, secure, centralized store for secrets, along with strong access controls, eliminating the need for developers to directly manage sensitive data within their applications.
  
- When building applications, we often make use of various “secrets” such as client IDs, access tokens, passwords, certificates, encryption keys, and API keys. Naturally, we need a secure way to store, manage, and control access to this sensitive data. Azure Key Vault provides a handy, cloud-based solution for this.
  
## Let's Create Azure Key Vault from Azure Portal
    
- **Step 1 -** Login into your Azure Portal and search for key vault afterward fill the required details and click on `Review + Create` as shown below :

  ![key0](https://github.com/jil1710/readmedemo/assets/125335932/dc81a3d8-2bf2-46a3-915e-c29ece8e4503)

- **Step 2 -** After the deployment of key vault is over click on `Go to resource` it will redirect to key vault that we created thenafter click on `Secrets`

  ![key0 1](https://github.com/jil1710/readmedemo/assets/125335932/c57388f9-0941-4398-95af-d6208b19130c)

- **Step 3 -** Click on `Generate/Import` to create new secrets in key vault fill the required key name and value then click on `Create`.

  ![key0 2](https://github.com/jil1710/readmedemo/assets/125335932/e467da5b-f913-4077-a5ce-2629a327b2d7)
  
  ![key1 1](https://github.com/jil1710/readmedemo/assets/125335932/0e4b27f8-4c12-43e0-9249-dfe7eb5b4dab)

- **Step 4 -** We successfully created key vault and secrets here but to access the secrets we need to provide access policy or use `new DefaultAzureCredential()`( Azure Account Credential ). To provide the access policy and gave the access to our secrets we need to register app that can use our secrets to do so follow the below process :

     - Search For App registration and click on new Registration then fill the required details.

        ![key0 3](https://github.com/jil1710/readmedemo/assets/125335932/77efc49e-d41c-449a-94a7-c9779feee7f4)

     - After that redirect to your register app in that click on overview tab and copy the `client id`, `tenent id` and to get the `client secret key` click on `Certificates & Secret` after that create new client secrets key and copy it. All this required for reading our secrets in key vault.

        ![key0 4](https://github.com/jil1710/readmedemo/assets/125335932/1efad340-a976-45f4-9748-46f4a45301fe)

- **Step 5 -** After go to our key vault section and in that gave access to our app that we register in above step-4. Go to -> your.key.vault -> Access Policies -> Create. You can gave get,set,delete etc.. access to your secrets via our registered app.

  ![image](https://github.com/jil1710/readmedemo/assets/125335932/f07aaf4d-d142-4db7-91ed-209a5005e814)

    - Select Key Management and gave the operation you perform on secrets such as read, get, set, list, recover, delete etc...

      ![image](https://github.com/jil1710/readmedemo/assets/125335932/b3bcc444-d0f6-4b70-a798-3ec13acb185c)

- **Step 6 -** Create .Net Core app or install below mention nuget package in order to communicate with key vault:

  ```csharp
      Azure.Extensions.AspNetCore.Configuration
  ```

  ```csharp
    Azure.Security.KeyVault.Secrets
  ```

  ```csharp
    Azure.Identity
  ```

- **Step 7 -** Configure or Add Azure Key Vault Service into Program.cs file and also add the  `client id`, `tenent id`, `client secret key`, `key vault url` into appsettings.json

  ```json
    "KeyVaultSecretConfiguration": {
      "KeyVaultURL": "key-vault-url",
      "ClientId": "client id",
      "ClientSecret": "client secret key",
      "TenantId": "tenant id"
    }
  ```
 
  ![image](https://github.com/jil1710/readmedemo/assets/125335932/817b2573-6951-40ee-9130-1a6309ba04a4)

  - Here our key name is `AzureBlob-ConnectionStrings--AzureBlobStorage` to access the secret key value then using IConfiguration interface we can access for eg : configuration["AzureBlob-ConnectionStrings--AzureBlobStorage"] but it's very long key and not a proper way to use so we simplified the key by implementing `KeyVaultSecretManager` let see the example :
 
    ![image](https://github.com/jil1710/readmedemo/assets/125335932/5e447f51-8bb4-4284-b695-b3cd189f14e7)

 - After that we can access the secret key value by proper method so below :

    ![image](https://github.com/jil1710/readmedemo/assets/125335932/40902cec-f047-4216-b0bd-91729c48a333)

