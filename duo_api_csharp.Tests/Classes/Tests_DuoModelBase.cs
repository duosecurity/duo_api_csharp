/*
 * Copyright (c) 2022-2024 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 * https://github.com/duosecurity/duo_api_csharp
 */

using duo_api_csharp.Models.v1;

namespace duo_api_csharp.Tests.Classes
{
    public class Tests_DuoModelBase
    {
        [Fact]
        public void Test_InheritedClass_ConvertsCorrectly()
        {
            var ChildClass = new DuoUserResponseModel
            {
                CreatedOn = DateTime.Now,
                Username = "Bob"
            };
            
            Assert.NotNull(ChildClass.CreatedOn);
            var ParentClass = Assert.IsType<DuoUserRequestModel>(ChildClass.GetBaseClass(typeof(DuoUserRequestModel)));
            Assert.IsNotType<DuoUserResponseModel>(ParentClass);
            Assert.Equal("Bob", ParentClass.Username);
        }
        
        [Fact]
        public void Test_MismatchedClass_ThrowsException()
        {
            var ChildClass = new DuoUserResponseModel
            {
                CreatedOn = DateTime.Now,
                Username = "Bob"
            };
            
            Assert.Throws<ArgumentException>(() => ChildClass.GetBaseClass(typeof(DuoGroupRequestModel)));
        }
    }
}