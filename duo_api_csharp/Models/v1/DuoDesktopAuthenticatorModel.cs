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
	/// Duo Desktop Authenticator request data
	/// This represents read-only API response data that cannot be updated via the API
	/// </summary>
    public class DuoDesktopAuthenticatorResponseModel : DuoModelBase
    {
		/// <summary>
		/// The authenticator's ID.
		/// </summary>
		[JsonProperty("daid")]
		public string? ID { get; set; }
		
		/// <summary>
		/// The authenticator's Duo-specific identifier.
		/// </summary>
		[JsonProperty("dakey")]
		public string? Key { get; set; }
		
		/// <summary>
		/// The endpoint's hostname.
		/// </summary>
		[JsonProperty("device_name")]
		public string? DeviceName { get; set; }
		
		/// <summary>
		/// The version of Duo Desktop installed on the endpoint.
		/// </summary>
		[JsonProperty("duo_desktop_version")]
		public string? DuoDesktopVersion { get; set; }
		
		/// <summary>
		/// The endpoint's operating system platform.
		/// </summary>
		[JsonProperty("os_family")]
		public string? OSFamily { get; set; }
		
		/// <summary>
		/// Selected information about the end user attached to this Desktop Authenticator.
		/// </summary>
		[JsonProperty("user")]
		public DuoUserResponseModel? User { get; set; }
    }
}