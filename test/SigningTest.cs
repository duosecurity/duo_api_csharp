/*
 * Copyright (c) 2018 Duo Security
 * All rights reserved
 */

using Duo;
using System.Collections.Generic;

using Microsoft.VisualStudio.TestTools.UnitTesting;

[TestClass]
public class SigningTest
{
    [TestMethod]
    public void HmacSha1()
    {
        var ikey = "test_ikey";
        var skey = "gtdfxv9YgVBYcF6dl2Eq17KUQJN2PLM2ODVTkvoT";
        var host = "foO.BAr52.cOm";
        var client = new Duo.DuoApi(ikey, skey, host);
        var method = "PoSt";
        var path = "/Foo/BaR2/qux";
        var date = "Fri, 07 Dec 2012 17:18:00 -0000";
        var parameters = new Dictionary<string, string>
            {
                {"\u469a\u287b\u35d0\u8ef3\u6727\u502a\u0810\ud091\xc8\uc170", "\u0f45\u1a76\u341a\u654c\uc23f\u9b09\uabe2\u8343\u1b27\u60d0"},
                {"\u7449\u7e4b\uccfb\u59ff\ufe5f\u83b7\uadcc\u900c\ucfd1\u7813", "\u8db7\u5022\u92d3\u42ef\u207d\u8730\uacfe\u5617\u0946\u4e30"},
                {"\u7470\u9314\u901c\u9eae\u40d8\u4201\u82d8\u8c70\u1d31\ua042", "\u17d9\u0ba8\u9358\uaadf\ua42a\u48be\ufb96\u6fe9\ub7ff\u32f3"},
                {"\uc2c5\u2c1d\u2620\u3617\u96b3F\u8605\u20e8\uac21\u5934", "\ufba9\u41aa\ubd83\u840b\u2615\u3e6e\u652d\ua8b5\ud56bU"},
            };
        string canon_params = DuoApi.CanonicalizeParams(parameters);
        var actual = client.Sign(method, path, canon_params, date);
        var expected = "Basic dGVzdF9pa2V5OmYwMTgxMWNiYmY5NTYxNjIzYWI0NWI4OTMwOTYyNjdmZDQ2YTUxNzg=";
        Assert.AreEqual(expected, actual);
    }
}