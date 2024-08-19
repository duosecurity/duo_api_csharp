/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
using System.Net;
using Newtonsoft.Json;

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
        
        /// <summary>
        /// Raw response data. Only set when no model is passed
        /// </summary>
        public string? RawResponseData { get; set; }
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
        [JsonProperty("stat")]
        public required string Status { get; set; }
        
        /// <summary>
        /// Metadata for the response from the server
        /// </summary>
        [JsonProperty("metadata")]
        public DuoResponseMetadataModel? ResponseMetadata { get; set; }
        
        /// <summary>
        /// In the case of an error, this will indcate a server side error code
        /// First three digits indicate the HTTP response code, the second two indicate a more specific error
        /// EG, 40002 = 400, Bad Request; 02 = Invalid request parameters
        /// </summary>
        [JsonProperty("code")]
        public int? ErrorCode { get; set; }
        
        /// <summary>
        /// In the case of an error, this will contain the description for the error code provided
        /// </summary>
        [JsonProperty("message")]
        public string? ErrorMessage { get; set; }
        
        /// <summary>
        /// In the case of an error, this will contain additional information, if available
        /// </summary>
        [JsonProperty("message_detail")]
        public string? ErrorMessageDetail { get; set; }
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
        [JsonProperty("response")]
        public T? Response { get; set; }
    }
    
    /// <summary>
    /// Paging metadata returned by the API
    /// https://duo.com/docs/adminapi#response-paging
    /// </summary>
    public class DuoResponseMetadataModel
    {
        /// <summary>
        /// An integer indicating the total number of objects retrieved by the API request across all pages of results.
        /// </summary>
        public int? TotalObjects { get; set; }
        
        /// <summary>
        /// An integer indicating The offset from 0 at which to start the next paged set of results.
        /// If not present in the metadata response, then there are no more pages of results left.
        /// </summary>
        public int? NextOffset { get; set; }
        
        /// <summary>
        /// An integer indicating the offset from 0 at which the previous paged set of results started.
        /// If you did not specify next_offset in the request, this defaults to 0 (the beginning of the results).
        /// </summary>
        public int? PrevOffset { get; set; }
    }
}