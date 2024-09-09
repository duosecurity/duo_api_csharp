/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using Newtonsoft.Json;
using duo_api_csharp.Classes;

namespace duo_api_csharp.Models.v1
{
	/// <summary>
	/// Duo Verification Push response data
	/// This represents read-only API response data that cannot be updated via the API
	/// </summary>
    public class DuoVerificationPushResponseModel : DuoModelBase
    {
        /// <summary>
        /// The ID of the Duo Push sent.
        /// </summary>
        [JsonProperty("push_id")]
        public string? PushID { get; set; }
        
        /// <summary>
        /// The Duo Push sent to the user contains this confirmation code.
        /// </summary>
        [JsonProperty("confirmation_code")]
        public string? ConfirmationCode { get; set; }
    }
	
	/// <summary>
	/// Duo Verification Push Validation response data
	/// This represents read-only API response data that cannot be updated via the API
	/// </summary>
    public class DuoVerificationValidationResponseModel : DuoModelBase
    {
        /// <summary>
        /// The ID of the Duo Push sent.
        /// </summary>
        [JsonProperty("push_id")]
        public string? PushID { get; set; }
        
        /// <summary>
        /// The result of the verification push sent. One of:
        /// approve: User approved the push.
        /// deny: User denied the push.
        /// fraud: User marked the push as fraud.
        /// waiting: User has not responded to the push yet.
        /// </summary>
        [JsonProperty("result")]
        public string? Result { get; set; }
    }
}