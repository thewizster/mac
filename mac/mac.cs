using System;
using System.Collections.Generic;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;

namespace Webextant.Security.Cryptography
{
    // General purpose class for working with HMAC SHA256 tokens
    public class Mac : imac
    {
        private string _secret = "";
        private Dictionary<string, string> _keyval;
        public Mac(string secret)
        {
            _secret = secret;
            ClearKeyVal();
        }
        // Validates a token against a string message
        public bool IsValid(string message, string token)
        {
            var testToken = CreateToken(message, _secret);
            return testToken == token;
        }
        // Validates a token against the concatenated values in the KeyVal dictionary
        public bool KeyValIsValid(string token)
        {
            var testToken = GenerateTokenFromKeyVal();
            return testToken == token;
        }
        // Generates a token for a string message
        public string GenerateToken(string message)
        {
            return CreateToken(message, _secret);
        }
        // Adds a Key Value pair to the internal dictionary
        public void AddKeyVal(string key, string value)
        {
            _keyval.Add(key, value);
        }
        // Clears all Key Value pairs from the internal dictionary
        public void ClearKeyVal()
        {
            _keyval = new Dictionary<string, string>();
        }
        // Generates a token using the internal dictionary values as the message
        public string GenerateTokenFromKeyVal()
        {
            string msg = "";
            foreach (var item in _keyval)
            {
                msg += item.Value;
            }
            return CreateToken(msg, _secret);
        }
        // Creates a token using the message string and secret
        private string CreateToken(string message, string secret)
        {
            secret = secret ?? "";
            var secretBin = CryptographicBuffer.ConvertStringToBinary(secret, BinaryStringEncoding.Utf8);
            var messageBin = CryptographicBuffer.ConvertStringToBinary(message, BinaryStringEncoding.Utf8);
            MacAlgorithmProvider macp = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            CryptographicHash hashMessage = macp.CreateHash(secretBin);
            hashMessage.Append(messageBin);
            return CryptographicBuffer.EncodeToBase64String(hashMessage.GetValueAndReset());
        }
    }
}