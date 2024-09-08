/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

namespace duo_api_csharp.Models
{
    /// <summary>
    /// Duo Request Data interface
    /// </summary>
    public interface DuoRequestData
    {
        /// <summary>
        /// Content-Type header to send in the request
        /// </summary>
        public string ContentTypeHeader { get; }
    }
    
    /// <summary>
    /// Duo Request data - Form Encoded Parameters
    /// </summary>
    public class DuoParamRequestData : DuoRequestData
    {
        /// <summary>
        /// Content-Type header to send in the request
        /// </summary>
        public string ContentTypeHeader => "application/x-www-form-urlencoded";
        
        /// <summary>
        /// Dictionary of parameters to send in the request
        /// </summary>
        public Dictionary<string,string> RequestData { get; init; } = new();
    }
    
    /// <summary>
    /// Duo Request data - JSON Data
    /// </summary>
    public class DuoJsonRequestData : DuoRequestData
    {
        /// <summary>
        /// Content-Type header to send in the request
        /// </summary>
        public string ContentTypeHeader => "application/json";
        
        /// <summary>
        /// JSON data serialised as a string
        /// </summary>
        public string RequestData { get; set; } = "";
    }
    
    /// <summary>
    /// Duo Request data - JSON Data
    /// </summary>
    /// <param name="jsonObj">JSON object to serialise</param>
    public class DuoJsonRequestDataObject(object jsonObj) : DuoRequestData
    {
        /// <summary>
        /// Content-Type header to send in the request
        /// </summary>
        public string ContentTypeHeader => "application/json";
        
        /// <summary>
        /// Object to serialise as JSON
        /// </summary>
        public object? RequestData { get; init; } = jsonObj;
    }
}