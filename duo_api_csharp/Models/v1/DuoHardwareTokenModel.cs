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
	/// Duo Hardware Token request data
	/// This represents read-write API response data that can also be used in an update request to the API
	/// </summary>
    public class DuoHardwareTokenRequestModel : DuoModelBase
    {
        /// <summary>
        /// The hardware token's unique ID.
        /// </summary>
        [JsonProperty("token_id")]
        public string? TokenID { get; set; }
        
        /// <summary>
        /// The serial number of the hardware token; used to uniquely identify the hardware token when paired with type.
        /// </summary>
        [JsonProperty("serial")]
        public string? Serial { get; set; }
        
        /// <summary>
        /// The type of hardware token. One of:
        /// "h6"	HOTP-6 hardware token
        /// "h8"	HOTP-8 hardware token
        /// "yk"	YubiKey AES hardware token
        /// "d1"    Duo-D100 tokens (NB: are imported when purchased from Duo and may not be created via the Admin API)
        /// </summary>
        [JsonProperty("type")]
        public string? Type { get; set; }

        /// <summary>
        /// The HOTP secret. This parameter is required for HOTP-6 and HOTP-8 hardware tokens.
        /// </summary>
        [JsonProperty("secret")]
        public string? Secret { get; set; }
        
        /// <summary>
        /// Initial value for the HOTP counter. This parameter is only valid for HOTP-6 and HOTP-8 hardware tokens. Default: 0.
        /// </summary>
        [JsonProperty("counter")]
        public string? Counter { get; set; }
        
        /// <summary>
        /// The 12-character hexadecimal YubiKey private ID. This parameter is required for YubiKey hardware tokens.
        /// </summary>
        [JsonProperty("private_id")]
        public string? PrivateID { get; set; }
        
        /// <summary>
        /// The 32-character hexadecimal YubiKey AES key. This parameter is required for YubiKey hardware tokens.
        /// </summary>
        [JsonProperty("aes_key")]
        public string? AESKey { get; set; }
        
    }
    
	/// <summary>
	/// Duo Hardware Token response data
	/// This represents read-only API response data that cannot be updated via the API
	/// This class inherits DuoHardwareTokenRequestModel
	/// </summary>
    public class DuoHardwareTokenResponseModel : DuoHardwareTokenRequestModel
    {
		/// <summary>
		/// A list of end users associated with this hardware token.
		/// </summary>
		[JsonProperty("users")]
		public IEnumerable<DuoUserResponseModel>? Users { get; set; }
		
		/// <summary>
		/// A list of administrators associated with this hardware token.
		/// </summary>
		[JsonProperty("admins")]
		public IEnumerable<DuoAdminResponseModel>? Admins { get; set; } 
    }
}