/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using Newtonsoft.Json;

namespace duo_api_csharp.Classes
{
    /// <summary>
    /// This exists because the Duo API is unable to accept anything other than strings
    /// Hopefully, this limitation will be removed in a future version iteration
    /// </summary>
    public class DuoBoolConverter : JsonConverter
    {
        public override void WriteJson(JsonWriter writer, object? value, JsonSerializer serializer)
        {
            var boolValue = (bool?)value;
            if( boolValue == null ) return;
            writer.WriteValue((bool)boolValue ? "true" : "false");
        }

        public override object? ReadJson(JsonReader reader, Type objectType, object? existingValue, JsonSerializer serializer)
        {
            return null;
        }

        public override bool CanRead
        {
            get
            {
                return false;
            }
        }

        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(bool);
        }
    }
}