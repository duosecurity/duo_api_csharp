using System.Text.Json.Serialization;

namespace duo_api_csharp.Models.v1
{
    public class DuoPhoneRequestModel
    {
        /// <summary>
        /// Phone Unique ID
        /// </summary>
        [JsonPropertyName("phone_id")]
        public string? PhoneID { get; set; }
    }
    
    public class DuoPhoneResponseModel : DuoPhoneRequestModel
    {
        
    }
}

/*"response": [
   {
   "activated": false,
   "capabilities": [
     "sms",
     "phone",
     "push"
   ],
   "encrypted": "Encrypted",
   "extension": "",
   "fingerprint": "Configured",
   "last_seen": "2019-03-04T15:04:04",
   "model": "Google Pixel 2 Xl",
   "name": "",
   "number": "+15035550102",
   "phone_id": "DPFZRS9FB0D46QFTM890",
   "platform": "Google Android",
   "postdelay": "",
   "predelay": "",
   "screenlock": "Locked",
   "sms_passcodes_sent": true,
   "tampered": "Not tampered",
   "type": "Mobile"
   },
   {
   "activated": false,
   "capabilities": [
     "phone"
   ].
   "encrypted": "",
   "extension": "",
   "fingerprint": "",
   "last_seen": "",
   "model": "Unknown",
   "name": "",
   "number": "+15035550103",
   "phone_id": "DPFZRS9FB0D46QFTM891",
   "platform": "Unknown",
   "postdelay": "",
   "predelay": "",
   "screenlock": "",
   "sms_passcodes_sent": false,
   "tampered": "",
   "type": "Landline"
   }*/