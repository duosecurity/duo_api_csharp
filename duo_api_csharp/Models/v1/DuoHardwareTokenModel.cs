using System.Text.Json.Serialization;

namespace duo_api_csharp.Models.v1
{
    public class DuoHardwareTokenRequestModel
    {
        /// <summary>
        /// Token Unique ID
        /// </summary>
        [JsonPropertyName("token_id")]
        public string TokenID { get; set; }
    }
    
    public class DuoHardwareTokenResponseModel : DuoHardwareTokenRequestModel
    {
        
    }
}

/*
    {
   "serial": "123456",
   "token_id": "DHEKH0JJIYC1LX3AZWO4",
   "totp_step": null,
   "type": "d1"
   },
   */