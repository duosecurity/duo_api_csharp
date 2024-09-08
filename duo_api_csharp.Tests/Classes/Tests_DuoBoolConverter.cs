/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using Newtonsoft.Json;
using System.Globalization;
using duo_api_csharp.Classes;

namespace duo_api_csharp.Tests.Classes
{
    public class Tests_DuoBoolConverter
    {
        [Fact]
        public void Test_WriteJson_ReturnsStringTrue_WithBooleanTrue()
        {
            // Create JSON Writer
            var sw = new StringWriter(CultureInfo.InvariantCulture);
            using var writer = new JsonTextWriter(sw);
            
            // Write true to it
            new DuoBoolConverter().WriteJson(writer, true, null!);
            
            // Inspect result
            Assert.Equal("\"true\"", sw.ToString());
        }
        
        [Fact]
        public void Test_WriteJson_ReturnsStringFalse_WithBooleanFalse()
        {
            // Create JSON Writer
            var sw = new StringWriter(CultureInfo.InvariantCulture);
            using var writer = new JsonTextWriter(sw);
            
            // Write true to it
            new DuoBoolConverter().WriteJson(writer, false, null!);
            
            // Inspect result
            Assert.Equal("\"false\"", sw.ToString());
        }
        
        [Fact]
        public void Test_ReadJson_ReturnsNull()
        {
            Assert.Null(new DuoBoolConverter().ReadJson(null!, null!, null!, null!));
        }
        
        [Fact]
        public void Test_CanRead_ReturnsFalse()
        {
            Assert.False(new DuoBoolConverter().CanRead);
        }
        
        [Fact]
        public void Test_CanConvert_ReturnsTrue_WithBoolean()
        {
            Assert.True(new DuoBoolConverter().CanConvert(typeof(bool)));
        }
        
        [Fact]
        public void Test_CanConvert_ReturnsFalse_WithString()
        {
            Assert.False(new DuoBoolConverter().CanConvert(typeof(string)));
        }
    }
}