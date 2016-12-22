using System;
using System.Collections.Generic;
using System.Text;

namespace Webextant.Security.Cryptography
{
    interface imac
    {
        bool IsValid(string message, string token);
        bool KeyValIsValid(string token);
        string GenerateToken(string message);
        void AddKeyVal(string key, string val);
        void ClearKeyVal();
        string GenerateTokenFromKeyVal();
    }
}
