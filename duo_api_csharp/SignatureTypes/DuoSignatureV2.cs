/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Text;
using duo_api_csharp.Models;
using duo_api_csharp.Extensions;
using System.Security.Cryptography;

namespace duo_api_csharp.SignatureTypes
{
    internal class DuoSignatureV2(string ikey, string skey, string host, DateTime requesttime) : IDuoSignatureTypes
    {
        public DuoSignatureTypes SignatureType => DuoSignatureTypes.Duo_SignatureTypeV2;
        public Dictionary<string, string> DefaultRequestHeaders => new()
        {
            { "X-Duo-Date", requesttime.DateToRFC822() }
        };

        public string SignRequest(HttpMethod method, string path, DateTime requestDate, DuoRequestData? requestData, Dictionary<string, string>? _)
        {
            // Return HMAC signature for request
            var signature = _GenerateSignature(method, path, requestDate, requestData);
            var auth = $"{ikey}:{_HmacSign($"{signature}")}";
            return _Encode64(auth);
        }
        
        internal string _GenerateSignature(HttpMethod method, string path, DateTime requestDate, DuoRequestData? requestData)
        {
            var signingHeader = $"{requestDate.DateToRFC822()}\n{method.Method.ToUpper()}\n{host}\n{path}";
            var signingParams = _CanonParams(requestData);
            return $"{signingHeader}\n{signingParams}";
        }
        
        internal string _CanonParams(DuoRequestData? requestData)
        {
            var signingParams = new StringBuilder();
            if( requestData is DuoParamRequestData data )
            {
                foreach( var (paramKey, paramValue) in data.RequestData.OrderBy(q => Uri.EscapeDataString(q.Key)) )
                {
                    if( signingParams.Length != 0 ) signingParams.Append('&');
                    signingParams.Append($"{Uri.EscapeDataString(paramKey)}={Uri.EscapeDataString(paramValue)}");
                }
            }
            
            return signingParams.ToString();
        }
        
        internal string? _HmacSign(string data)
        {
            var key_bytes = Encoding.UTF8.GetBytes(skey);
            var hmac = new HMACSHA512(key_bytes);

            var data_bytes = Encoding.UTF8.GetBytes(data);
            hmac.ComputeHash(data_bytes);
            if( hmac.Hash == null ) return null;

            var hex = BitConverter.ToString(hmac.Hash);
            return hex.Replace("-", "").ToLower();
        }

        internal string _Encode64(string plaintext)
        {
            var plaintext_bytes = Encoding.UTF8.GetBytes(plaintext);
            return Convert.ToBase64String(plaintext_bytes);
        }
    }
}