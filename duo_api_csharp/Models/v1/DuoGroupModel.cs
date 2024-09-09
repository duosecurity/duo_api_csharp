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
	/// Duo Group request data
	/// This represents read-write API response data that can also be used in an update request to the API
	/// </summary>
    public class DuoGroupRequestModel : DuoModelBase
    {
        /// <summary>
        /// Group ID
        /// </summary>
        [JsonProperty("group_id")]
        public string? GroupID { get; set; }
        
        /// <summary>
        /// The group's name.
        /// If managed by directory sync, then the name returned here also indicates the source directory.
        /// </summary>
        [JsonProperty("name")]
        public string? Name { get; set; }
        
        /// <summary>
        /// The group's description.
        /// </summary>
        [JsonProperty("desc")]
        public string? Description { get; set; }
        
        /// <summary>
        /// The group's authentication status. May be one of:
        /// "Active"	The users in the group must complete secondary authentication.
        /// "Bypass"	The users in the group will bypass secondary authentication after completing primary authentication.
        /// "Disabled"	The users in the group will not be able to authenticate.
        /// </summary>
        [JsonProperty("status")]
        public string? Status { get; set; }
    }
    
	/// <summary>
	/// Duo Group response data
	/// This represents read-only API response data that cannot be updated via the API
	/// This class inherits DuoGroupRequestModel
	/// </summary>
    public class DuoGroupResponseModel : DuoGroupRequestModel;
}