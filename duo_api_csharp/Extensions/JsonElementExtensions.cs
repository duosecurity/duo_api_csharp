/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */
 
using System.Text.Json;
using System.Collections;

namespace duo_api_csharp.Extensions
{ 
    internal static class JsonElementExtensions
    {
        /// <summary>
        /// Converts a value contained within a System.Text.Json.JsonElement
        /// into an object of the contained type
        /// </summary>
        /// <param name="element"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        internal static object? ConvertToObject(this JsonElement element)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Undefined:
                case JsonValueKind.Null:
                    return null;
                case JsonValueKind.String:
                    return element.GetString();
                case JsonValueKind.Number:
                    if (element.TryGetInt32(out int intValue))
                    {
                        return intValue;
                    }
                    if (element.TryGetInt64(out long longValue))
                    {
                        return longValue;
                    }
                    if (element.TryGetDecimal(out decimal decimalValue))
                    {
                        return decimalValue;
                    }
                    return element.GetDouble();
                case JsonValueKind.True:
                case JsonValueKind.False:
                    return element.GetBoolean();
                case JsonValueKind.Object:
                    var sourceDict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(element.GetRawText());
                    var targetDict = new Dictionary<string, object>();
                    if( sourceDict == null ) return null;
                    foreach (var kvp in sourceDict)
                    {
                        var convertedValue = kvp.Value.ConvertToObject();
                        if( convertedValue != null ) targetDict.Add(kvp.Key, convertedValue);
                    }
                    return targetDict;
                case JsonValueKind.Array:
                    // ArrayList was returned by the older serializer, so make sure to keep the type
                    var list = new ArrayList();
                    foreach (var item in element.EnumerateArray())
                    {
                        list.Add(item.ConvertToObject());
                    }
                    return list;
                default:
                    throw new InvalidOperationException("Unexpected JSON value kind: " + element.ValueKind);
            }
        }
    }
}
