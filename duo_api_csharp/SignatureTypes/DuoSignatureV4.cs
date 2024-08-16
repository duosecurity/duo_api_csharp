/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Web;
using System.Text;
using duo_api_csharp.Extensions;
using System.Security.Cryptography;

namespace duo_api_csharp.SignatureTypes
{
    public class DuoSignatureV4(string ikey, string skey, string host, DateTime requesttime) : IDuoSignatureTypes
    {
        public DuoSignatureTypes SignatureType => DuoSignatureTypes.Duo_SignatureTypeV4;
        public Dictionary<string, string> DefaultRequestHeaders => new()
        {
            { "X-Duo-Date", requesttime.DateToRFC822() }
        };

        public string SignRequest(HttpMethod method, string path, Dictionary<string, string>? requestData, DateTime requestDate, Dictionary<string, string> _)
        {
            // Format data for signature
            var signingHeader = $"{requestDate.DateToRFC822()}\n{method.Method.ToUpper()}\n{host}\n{path}";
            var signingParams = new StringBuilder();
            if( requestData != null )
            {
                foreach( var (paramKey, paramValue) in requestData )
                {
                    if( signingParams.Length != 0 ) signingParams.Append('&');
                    signingParams.Append($"{HttpUtility.UrlEncode(paramKey)}={HttpUtility.UrlEncode(paramValue)}");
                }
            }
            
            // Return HMAC signature for request
            var auth = $"{ikey}:{_HmacSign($"{signingHeader}\n{signingParams}")}";
            return _Encode64(auth);
        }
        
        private string? _HmacSign(string data)
        {
            var key_bytes = Encoding.ASCII.GetBytes(skey);
            var hmac = new HMACSHA512(key_bytes);

            var data_bytes = Encoding.ASCII.GetBytes(data);
            hmac.ComputeHash(data_bytes);
            if( hmac.Hash == null ) return null;

            var hex = BitConverter.ToString(hmac.Hash);
            return hex.Replace("-", "").ToLower();
        }

        private static string _Encode64(string plaintext)
        {
            var plaintext_bytes = Encoding.ASCII.GetBytes(plaintext);
            return Convert.ToBase64String(plaintext_bytes);
        }
    }
}