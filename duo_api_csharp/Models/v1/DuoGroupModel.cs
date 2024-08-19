using System.Text.Json.Serialization;

namespace duo_api_csharp.Models.v1
{
    public class DuoGroupRequestModel
    {
        /// <summary>
        /// Group ID
        /// </summary>
        [JsonPropertyName("group_id")]
        public string? GroupID { get; set; }
    }
    
    public class DuoGroupResponseModel : DuoGroupRequestModel
    {
        
    }
}

/*
    {
   "desc": "This is group A",
   "group_id": "DGBDKSSH37KSJ373JKSU",
   "mobile_otp_enabled": false,    
   "name": "Group A",
   "push_enabled": false,
   "sms_enabled": false,
   "status": "Active",
   "voice_enabled": false
   },
   */