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
	/// Duo User request data
	/// This represents read-write API response data that can also be used in an update request to the API
	/// </summary>
	public class DuoUserRequestModel
	{
		/// <summary>
		/// Unique ID of the user
		/// </summary>
		[JsonProperty("user_id")]
		public string? UserID { get; set; }
		
		/// <summary>
		/// Username
		/// </summary>
		[JsonProperty("username")]
		public string? Username { get; set; }
		
		/// <summary>
		/// Map of the user's username alias(es). Up to eight aliases may exist.
		/// </summary>
		[JsonProperty("aliases")]
		public Dictionary<string, string>? Aliases { get; set; }
		
		/// <summary>
		/// The user's real name (or full name).
		/// </summary>
		[JsonProperty("realname")]
		public string? RealName { get; set; }
		
		/// <summary>
		/// Email Address
		/// </summary>
		[JsonProperty("email")]
		public string? Email { get; set; }
		
		/// <summary>
		/// If true, the user is automatically prompted to use their last-used authentication method when authenticating.
		/// If false, the user is shown a list of authentication methods to initiate authentication.
		/// Only effective in the Universal Prompt.
		/// </summary>
		[JsonProperty("enable_auto_prompt")]
		public bool? EnableAutoPrompt { get; set; }
		
		/// <summary>
		/// The user's status. One of:
		/// "active"			The user must complete secondary authentication.
		/// "bypass"			The user will bypass secondary authentication after completing primary authentication.
		/// "disabled"			The user will not be able to log in.
		/// "locked out"		The user has been locked out due to a specific reason stored in the “lockout_reason” field.
		/// "pending deletion"	The user was marked for deletion by a Duo admin from the Admin Panel, by the system for inactivity, or by directory sync. If not restored within seven days the user is permanently deleted.
		/// Note that when a user is a member of a group, the group status may override the individual user's status. Group status is not shown in the user response.
		/// </summary>
		[JsonProperty("status")]
		public string? Status { get; set; }
		
		/// <summary>
		/// Notes about this user. Viewable in the Duo Admin Panel.
		/// </summary>
		[JsonProperty("notes")]
		public string? Notes { get; set; }
	}
	
	/// <summary>
	/// Duo User response data
	/// This represents read-only API response data that cannot be updated via the API
	/// This class inherits DuoUserRequestModel
	/// </summary>
	public class DuoUserResponseModel : DuoUserRequestModel
	{
		[JsonProperty("created")]
		private long? _CreatedOn { get; set; }
		
		/// <summary>
		/// The user's creation date
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
		
		/// <summary>
		/// The user's unique identifier imported by a directory sync.
		/// This is the id if the user is synced from Entra ID or object_guid if the user is synced from Active Directory.
		/// Not returned for users managed by OpenLDAP sync or users not managed by a directory sync.
		/// </summary>
		[JsonProperty("external_id")]
		public string? ExternalID { get; set; }
		
		/// <summary>
		/// List of groups to which this user belongs.
		/// </summary>
		[JsonProperty("groups")]
		public IEnumerable<DuoGroupResponseModel>? Groups { get; set; }
		
		/// <summary>
		/// Is true if the user has a phone, hardware token, U2F token, WebAuthn security key, or other WebAuthn method available for authentication.
		/// Otherwise, false.
		/// </summary>
		[JsonProperty("is_enrolled")]
		public bool? IsEnrolled { get; set; }
		
		[JsonProperty("last_directory_sync")]
		private long? _LastDirectorySync { get; set; }
		
		/// <summary>
		/// An integer indicating the last update to the user via directory sync as a Unix timestamp,
		/// or null if the user has never synced with an external directory or if the directory that originally created the user has been deleted from Duo.
		/// </summary>
		[NotMapped]
		public DateTime? LastDirectorySync
		{
			get
			{
				return Epoch.FromUnix(_LastDirectorySync);
			}
			set
			{
				_LastDirectorySync = Epoch.ToUnix(value);
			}
		}
		
		[JsonProperty("last_login")]
		private long? _LastLogin { get; set; }
		
		/// <summary>
		/// An integer indicating the last time this user logged in, as a Unix timestamp,
		/// or null if the user has not logged in.
		/// </summary>
		[NotMapped]
		public DateTime? LastLogin
		{
			get
			{
				return Epoch.FromUnix(_LastLogin);
			}
			set
			{
				_LastLogin = Epoch.ToUnix(value);
			}
		}
		
		/// <summary>
		/// The user's lockout_reason. One of:
		/// "Failed Attempts"		The user was locked out due to excessive authentication attempts.
		/// "Not enrolled"			The user was locked out due to being not enrolled for a given period of time after the user was created.
		/// "Admin disabled"		The user was locked out by an admin from Duo Trust Monitor.
		/// "Admin API disabled"	The user's status was set to "locked out" by Admin API.
		/// </summary>
		[JsonProperty("lockout_reason")]
		public string? LockoutReason { get; set; }
		
		/// <summary>
		/// A list of phones that this user can use.
		/// </summary>
		[JsonProperty("phones")]
		public IEnumerable<DuoPhoneResponseModel>? Phones { get; set; }
		
		/// <summary>
		/// A list of hardware tokens that this user can use.
		/// </summary>
		[JsonProperty("tokens")]
		public IEnumerable<DuoHardwareTokenResponseModel>? HardwareTokens { get; set; }
		
		/// <summary>
		/// A list of WebAuthn authenticators that this user can use.
		/// </summary>
		[JsonProperty("webauthncredentials")]
		public IEnumerable<DuoWebAuthNResponseModel>? WebAuthNCredentials { get; set; }
	}
}