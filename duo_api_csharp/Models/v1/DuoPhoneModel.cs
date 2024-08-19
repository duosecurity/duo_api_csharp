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
	/// Duo Phone request data
	/// This represents read-write API response data that can also be used in an update request to the API
	/// </summary>
    public class DuoPhoneRequestModel : DuoModelBase
    {
        /// <summary>
        /// Phone Unique ID
        /// </summary>
        [JsonProperty("phone_id")]
        public string? PhoneID { get; set; }
        
        /// <summary>
        /// The phone number; E.164 format recommended (i.e. "+17345551212").
        /// If no leading plus sign is provided then it is assumed to be a United States number and an implicit "+1" country code is prepended. Dashes and spaces are ignored.
        /// A phone with a smartphone platform but no number is a tablet.
        /// </summary>
        [JsonProperty("number")]
        public string? Number { get; set; }
        
        /// <summary>
        /// Free-form label for the phone.
        /// </summary>
        [JsonProperty("name")]
        public string? Name { get; set; }
        
        /// <summary>
        /// The extension.
        /// </summary>
        [JsonProperty("extension")]
        public string? Extension { get; set; }
        
        /// <summary>
        /// The phone type.
        /// One of: "unknown", "mobile", or "landline".
        /// </summary>
        [JsonProperty("type")]
        public string? Type { get; set; }
        
        /// <summary>
        /// The phone platform.
        /// One of: "unknown", "google android", "apple ios", "windows phone 7", "rim blackberry", "java j2me", "palm webos", "symbian os", "windows mobile", or "generic smartphone".
        /// "windows phone" is accepted as a synonym for "windows phone 7". This includes devices running Windows Phone 8.
        /// If a smartphone's exact platform is unknown but it will have Duo Mobile installed, use "generic smartphone" and generate an activation code.
        /// When the phone is activated its platform will be automatically detected.
        /// </summary>
        [JsonProperty("platform")]
        public string? Platform { get; set; }
        
        /// <summary>
        /// The time (in seconds) to wait after the number picks up and before dialing the extension.
        /// </summary>
        [JsonProperty("predelay")]
        public string? PreDelay { get; set; }
        
        /// <summary>
        /// The time (in seconds) to wait after the extension is dialed and before the speaking the prompt.
        /// </summary>
        [JsonProperty("postdelay")]
        public string? PostDelay { get; set; }
    }
    
	/// <summary>
	/// Duo Phone response data
	/// This represents read-only API response data that cannot be updated via the API
	/// This class inherits DuoPhoneRequestModel
	/// </summary>
    public class DuoPhoneResponseModel : DuoPhoneRequestModel
    {
		/// <summary>
		/// Has this phone been activated for Duo Mobile yet? Either true or false.
		/// </summary>
		[JsonProperty("activated")]
		[JsonConverter(typeof(DuoBoolConverter))]
		public bool? Activated { get; set; }
    
        /// <summary>
        /// List of strings, each a factor that can be used with the device.
        /// "auto"			The device is valid for automatic factor selection (e.g. phone or push).
        /// "push"			The device is activated for Duo Push.
        /// "phone"			The device can receive phone calls.
        /// "sms"			The device can receive batches of SMS passcodes.
        /// "mobile_otp"	The device can generate passcodes with Duo Mobile.
        /// </summary>
        [JsonProperty("capabilities")]
        public IEnumerable<string>? Capabilities { get; set; }
    
        /// <summary>
        /// The encryption status of an Android or iOS device file system.
        /// One of: "Encrypted", "Unencrypted", or "Unknown". Blank for other platforms.
        /// This information is available to Duo Premier and Duo Advantage plan customers.
        /// </summary>
        [JsonProperty("encrypted")]
        public string? Encrypted { get; set; }
    
		/// <summary>
        /// Whether an Android or iOS phone is configured for biometric verification.
        /// One of: "Configured", "Disabled", or "Unknown". Blank for other platforms.
        /// This information is available to Duo Premier and Duo Advantage plan customers.
        /// </summary>
        [JsonProperty("fingerprint")]
        public string? Fingerprint { get; set; }
        
        /// <summary>
        /// Whether screen lock is enabled on an Android or iOS phone.
        /// One of: "Locked", "Unlocked", or "Unknown". Blank for other platforms.
        /// This information is available to Duo Premier and Duo Advantage plan customers.
        /// </summary>
        [JsonProperty("screenlock")]
        public string? Screenlock { get; set; }
        
        /// <summary>
        /// Whether an iOS or Android device is jailbroken or rooted.
        /// One of: "Not Tampered", "Tampered", or "Unknown". Blank for other platforms.
        /// This information is available to Duo Premier and Duo Advantage plan customers.
        /// </summary>
        [JsonProperty("tampered")]
        public string? Tampered { get; set; }
    
		/// <summary>
        /// The phone's model.
        /// </summary>
        [JsonProperty("model")]
        public string? Model { get; set; }
    
		/// <summary>
		/// Have SMS passcodes been sent to this phone? Either true or false.
		/// </summary>
		[JsonProperty("sms_passcodes_sent")]
		[JsonConverter(typeof(DuoBoolConverter))]
		public bool? SMSPasscodesSent { get; set; }
    
		[JsonProperty("last_seen")]
		private long? _LastSeen { get; set; }
		
		/// <summary>
		/// Time of the last contact between Duo's service and the activated Duo Mobile app installed on the phone.
		/// Null if the device has never activated Duo Mobile or if the platform does not support it.
		/// </summary>
		[NotMapped]
		public DateTime? LastSeenOn
		{
			get
			{
				return Epoch.FromUnix(_LastSeen);
			}
			set
			{
				_LastSeen = Epoch.ToUnix(value);
			}
		}
    
		/// <summary>
		/// A list of end users associated with this hardware token.
		/// </summary>
		[JsonProperty("users")]
		public IEnumerable<DuoUserResponseModel>? Users { get; set; }
    }
}