/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp.Classes;

namespace duo_api_csharp.Tests.Classes
{
    public class Tests_DuoEpoch
    {
        [Fact]
        public void Test_FromUnix_WithNull_ReturnsNull()
        {
            Assert.Null(Epoch.FromUnix(null));
        }
        
        [Fact]
        public void Test_FromUnix_ReturnsValidStamp()
        {
			var RefDate = new DateTime(2024, 8, 31, 22, 0, 0, DateTimeKind.Utc);
			var Converted = Epoch.FromUnix(1725141600);
            Assert.Equal(DateTimeKind.Utc, Converted!.Value.Kind);
            Assert.Equal(RefDate, Converted);
        }
        
        [Fact]
        public void Test_ToUnix_WithNull_ReturnsNull()
        {
            Assert.Null(Epoch.ToUnix(null));
        }
        
        [Fact]
        public void Test_ToUnix_ReturnsValidStamp()
        {
			var RefDate = new DateTime(2024, 8, 31, 22, 0, 0, DateTimeKind.Utc);
			var Converted = Epoch.ToUnix(RefDate); //1725141600
            Assert.Equal(1725141600, Converted);
        }
        
        [Fact]
        public void Test_Now_ReturnsValidStamp()
        {
            Assert.Equal(Epoch.ToUnix(DateTime.UtcNow), Epoch.Now);
        }
    }
}