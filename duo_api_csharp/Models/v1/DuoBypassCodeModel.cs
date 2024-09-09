/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using Newtonsoft.Json;
using duo_api_csharp.Classes;
using System.ComponentModel.DataAnnotations.Schema;

namespace duo_api_csharp.Models.v1
{
	/// <summary>
	/// Duo Bypass Code request data
	/// This represents read-write API response data that can also be used in an update request to the API
	/// </summary>
    public class DuoBypassCodeRequestModel : DuoModelBase
    {
		/// <summary>
		/// The email address of the Duo administrator who created the bypass code.
		/// </summary>
		[JsonProperty("admin_email")]
		public string? AdminEmail { get; set; }
		
		/// <summary>
		/// The bypass code's identifier. Use with GET bypass code by ID.
		/// </summary>
		[JsonProperty("bypass_code_id")]
		public string? BypassCodeID { get; set; }
		
		[JsonProperty("created")]
		private long? _CreatedOn { get; set; }
		
		/// <summary>
		/// The bypass code creation date
		/// </summary>
		[NotMapped]
		public DateTime? CreatedOn
		{
			get
			{
				return Epoch.FromUnix(_CreatedOn);
			}
			set
			{
				_CreatedOn = Epoch.ToUnix(value);
			}
		}
		
		[JsonProperty("expiration")]
		private long? _ExpiresOn { get; set; }
		
		/// <summary>
		/// An integer indicating the expiration timestamp of the bypass code,
		/// or null if the bypass code does not expire on a certain date.
		/// </summary>
		[NotMapped]
		public DateTime? ExpiresOn
		{
			get
			{
				return Epoch.FromUnix(_ExpiresOn);
			}
			set
			{
				_ExpiresOn = Epoch.ToUnix(value);
			}
		}
		
		/// <summary>
		/// An integer indicating the number of times the bypass code may be used before expiring,
		/// or null if the bypass code has no limit on the number of times it may be used.
		/// </summary>
		[JsonProperty("reuse_count")]
		public int? ReuseCount { get; set; }
    }
    
	/// <summary>
	/// Duo Bypass Code response data
	/// This represents read-only API response data that cannot be updated via the API
	/// This class inherits DuoBypassCodeRequestModel
	/// </summary>
	public class DuoBypassCodeResponseModel : DuoBypassCodeRequestModel
	{
		/// <summary>
		/// Selected information about the end user attached to this bypass code.
		/// </summary>
		[JsonProperty("user")]
		public DuoUserResponseModel? User { get; set; }
	}
}