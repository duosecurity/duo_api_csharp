/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using System.Text;
using Newtonsoft.Json;
using duo_api_csharp.Models;
using duo_api_csharp.Extensions;
using System.Security.Cryptography;

namespace duo_api_csharp.SignatureTypes
{
    internal class DuoSignatureV5(string ikey, string skey, string host, DateTime requesttime) : IDuoSignatureTypes
    {
        private readonly List<string> _AddedHeaders = [];
        
        public DuoSignatureTypes SignatureType => DuoSignatureTypes.Duo_SignatureTypeV5;
        public Dictionary<string, string> DefaultRequestHeaders => new()
        {
            { "X-Duo-Date", requesttime.DateToRFC822() }
        };
        
        public string SignRequest(HttpMethod method, string path, DateTime requestDate, DuoRequestData? requestData, Dictionary<string, string>? requestHeaders)
        {
            // Return HMAC signature for request
            var signature = _GenerateSignature(method, path, requestDate, requestData, requestHeaders);
            var auth = $"{ikey}:{_HmacSign($"{signature}")}";
            return _Encode64(auth);
        }
        
        internal string _GenerateSignature(HttpMethod method, string path, DateTime requestDate, DuoRequestData? requestData, Dictionary<string, string>? requestHeaders)
        {
            var signingHeader = $"{requestDate.DateToRFC822()}\n{method.Method.ToUpper()}\n{host}\n{path}";
            var signingParams = "";
            var bodyData = "";
            
            // Check request data for signing
            if( requestData is DuoParamRequestData paramData )
            {
                signingParams = _CanonParams(paramData);
            }
            else if( requestData is DuoJsonRequestData jsonData )
            {
                bodyData = jsonData.RequestData;
            }
            else if( requestData is DuoJsonRequestDataObject { RequestData: not null } jsonDataWithObject )
            {
                var jsonFormattingSettings = new JsonSerializerSettings
                {
                    NullValueHandling = NullValueHandling.Ignore
                };
                
                bodyData = JsonConvert.SerializeObject(jsonDataWithObject.RequestData, jsonFormattingSettings);
            }
            
            // Format hash of X-Duo headers
            var signingHeaders = new StringBuilder();
            if( requestHeaders != null )
            {
                lock( _AddedHeaders) 
                {
                    foreach( var (paramKey, paramValue) in requestHeaders )
                    {
                        if( !_ValidateHeader(paramKey, paramValue) ) continue;
                        _AddedHeaders.Add(paramKey.ToLower());
                        
                        if( signingHeaders.Length != 0 ) signingHeaders.Append('\x00');
                        signingHeaders.Append(paramKey.ToLower());
                        signingHeaders.Append('\x00');
                        signingHeaders.Append(paramValue);
                    }
                    
                    _AddedHeaders.Clear();
                }
            }
            
            return $"{signingHeader}\n{signingParams}\n{_Sha512Hash(bodyData)}\n{_Sha512Hash(signingHeaders.ToString())}";
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
        
        private string? _HmacSign(string data)
        {
            var key_bytes = Encoding.UTF8.GetBytes(skey);
            var hmac = new HMACSHA512(key_bytes);

            var data_bytes = Encoding.UTF8.GetBytes(data);
            hmac.ComputeHash(data_bytes);
            if( hmac.Hash == null ) return null;

            var hex = BitConverter.ToString(hmac.Hash);
            return hex.Replace("-", "").ToLower();
        }
        
        private string _Sha512Hash(string data)
        {
            var data_bytes = Encoding.UTF8.GetBytes(data);
            var hash_data = SHA512.HashData(data_bytes);
            var hex = BitConverter.ToString(hash_data);
            return hex.Replace("-", "").ToLower();
        }

        private string _Encode64(string plaintext)
        {
            var plaintext_bytes = Encoding.UTF8.GetBytes(plaintext);
            return Convert.ToBase64String(plaintext_bytes);
        }
        
        private bool _ValidateHeader(string headername, string value)
        {
            if( string.IsNullOrEmpty(headername) || string.IsNullOrEmpty(value) ) return false;
            if( headername.Contains('\x00') || value.Contains('\x00') ) return false;
            if( !headername.ToLower().Contains("x-duo-") ) return false;
            return !_AddedHeaders.Contains(headername.ToLower());
        }
    }
}