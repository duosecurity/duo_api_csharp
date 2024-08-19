using System.Text.Json.Serialization;

namespace duo_api_csharp.Models.v1
{
    public class DuoUserRequestModel
    {
        [JsonPropertyName("user_id")]
        public string? UserID { get; set; } = null;
        
        [JsonPropertyName("email")]
        public string? Email { get; set; } = null;
        
        [JsonPropertyName("username")]
        public string? Username { get; set; } = null;
    }
    
    public class DuoUserResponseModel : DuoUserRequestModel
    {
      
    }
}


/*
     {
       "alias1": "joe.smith",
       "alias2": "jsmith@example.com",
       "alias3": null,
       "alias4": null,
       "aliases": {
         "alias1": "joe.smith",
         "alias2": "jsmith@example.com"
       },
       "created": 1489612729,
       "email": "jsmith@example.com",
       "enable_auto_prompt": true,
       "external_id": "1a2345b6-7cd8-9e0f-g1hi-23j45kl6m789",
       "firstname": "",
       "groups": [
         {
         "desc": "People with hardware tokens",
         "group_id": "DGBDKSSH37KSJ373JKSU",
         "mobile_otp_enabled": false,
         "name": "token_users",
         "push_enabled": false,
         "sms_enabled": false,
         "status": "Active",
         "voice_enabled": false  
         }
       ],
       "is_enrolled": true,
       "last_directory_sync": 1508789163,
       "last_login": 1343921403,
       "lastname": "",
       "lockout_reason": null,
       "notes": "",
       "phones": [
         {
         "activated": true,
         "capabilities": [
           "auto",
           "push",
           "sms",
           "phone",
           "mobile_otp"
         ],
         "encrypted": "Encrypted",
         "extension": "",
         "fingerprint": "Configured",
         "last_seen": "2019-11-18T15:51:13",
         "model": "Apple iPhone 11 Pro",
         "name": "My iPhone",
         "number": "15555550100",
         "phone_id": "DPFZRS9FB0D46QFTM899",
         "platform": "Apple iOS",
         "postdelay": "0",
         "predelay": "0",
         "screenlock": "Locked",
         "sms_passcodes_sent": true,
         "tampered": "Not tampered",
         "type": "Mobile"
         }
       ],
       "realname": "Joe Smith",
       "status": "active",
       "tokens": [
         {
         "serial": "123456",
         "token_id": "DHIZ34ALBA2445ND4AI2",
         "type": "d1"
         }
       ],
       "u2ftokens": [],
       "user_id": "DU3RP9I2WOC59VZX672N",
       "username": "jsmith",
       "webauthncredentials": [
         {
         "credential_name": "Touch ID",
         "date_added": 1550685154,
         "label": "Touch ID",
         "webauthnkey": "WABFEOE007ZMV1QAZTRB"
         },
         {
         "credential_name": "YubiKey C",
         "date_added": 1550674764,
         "label": "Security Key",
         "webauthnkey": "WA4BD9AUVMSNUFWZGES4"
         }
       ],
     },
    */