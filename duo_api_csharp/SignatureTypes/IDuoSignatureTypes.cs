/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp.Models;

namespace duo_api_csharp.SignatureTypes
{
    public enum DuoSignatureTypes
    {
        Duo_SignatureTypeV2 = 2,
        Duo_SignatureTypeV4 = 4,
        Duo_SignatureTypeV5 = 5
    }
    
    public interface IDuoSignatureTypes
    {
        /// <summary>
        /// The version of signature this class implements
        /// </summary>
        public DuoSignatureTypes SignatureType { get; }
        
        /// <summary>
        /// Additional request headers added by this signature type that must be sent
        /// </summary>
        public Dictionary<string, string> DefaultRequestHeaders { get; }
        
        /// <summary>
        /// Sign the request
        /// </summary>
        /// <param name="method">HTTP Method</param>
        /// <param name="path">Path to endpoint</param>
        /// <param name="requestDate">Request date for X-Duo-Date header</param>
        /// <param name="requestData">Data being sent to the server</param>
        /// <param name="requestHeaders">Request headers</param>
        /// <returns>Signed bearer token</returns>
        public string SignRequest(HttpMethod method, string path, DateTime requestDate, DuoRequestData? requestData, Dictionary<string, string>? requestHeaders);
    }
}