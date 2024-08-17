/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
using System.Net;
using System.Text.Json.Serialization;

namespace duo_api_csharp.Models
{
    /// <summary>
    /// API Response Wrapper
    /// </summary>
    public class DuoAPIResponse
    {
        /// <summary>
        /// The status code of the response
        /// </summary>
        public required HttpStatusCode StatusCode { get; init; }
        
        /// <summary>
        /// If your request was successful or not
        /// </summary>
        public required bool RequestSuccess { get; init; }
        
        /// <summary>
        /// The response data from the server
        /// </summary>
        public DuoResponseModel? ResponseData { get; set; }
    }
    
    /// <summary>
    /// API Response Wrapper
    /// </summary>
    public class DuoAPIResponse<T>
    {
        /// <summary>
        /// The status code of the response
        /// </summary>
        public required HttpStatusCode StatusCode { get; init; }
        
        /// <summary>
        /// If your request was successful or not
        /// </summary>
        public required bool RequestSuccess { get; init; }
        
        /// <summary>
        /// The response data from the server
        /// </summary>
        public DuoResponseModel<T>? ResponseData { get; set; }
    }
    
    /// <summary>
    /// Duo API Response Model
    /// https://duo.com/docs/adminapi#response-format
    /// </summary>
    public class DuoResponseModel
    {
        /// <summary>
        /// Response from the server on the request
        /// Known values are OK and FAIL
        /// </summary>
        [JsonPropertyName("stat")]
        public required string Status { get; set; }
        
        /// <summary>
        /// In the case of an error, this will indcate a server side error code
        /// First three digits indicate the HTTP response code, the second two indicate a more specific error
        /// EG, 40002 = 400, Bad Request; 02 = Invalid request parameters
        /// </summary>
        [JsonPropertyName("code")]
        public int? ErrorCode { get; set; } = null;
        
        /// <summary>
        /// In the case of an error, this will contain the description for the error code provided
        /// </summary>
        [JsonPropertyName("message")]
        public string? ErrorMessage { get; set; } = null;
        
        /// <summary>
        /// In the case of an error, this will contain additional information, if available
        /// </summary>
        [JsonPropertyName("message_detail")]
        public string? ErrorMessageDetail { get; set; } = null;
    }
    
    /// <summary>
    /// Duo API Response Model
    /// https://duo.com/docs/adminapi#response-format
    /// </summary>
    public class DuoResponseModel<T> : DuoResponseModel
    {
        /// <summary>
        /// The response data from the request
        /// </summary>
        [JsonPropertyName("response")]
        public required T Response { get; set; }
    }
}