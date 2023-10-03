
using Azure.Security.KeyVault.Secrets;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration.AzureKeyVault;

namespace AzureKeyVault
{
    public class PrefixKeyVaultManager : IKeyVaultSecretManager
    {
        private readonly string _keyPrefix;

        public PrefixKeyVaultManager(string keyPrefix)
        {
            _keyPrefix = $"{keyPrefix}-";
        }

        public bool Load(SecretItem secret)
        {
            var result = secret.Identifier.Name.StartsWith(_keyPrefix);
            return result;
        }

        public string GetKey(SecretBundle secret)
        {
            var result = secret.SecretIdentifier.Name.Substring(_keyPrefix.Length).Replace("--", ConfigurationPath.KeyDelimiter);
            return result;
        }
    }
}
