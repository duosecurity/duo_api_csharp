/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using Duo;
using System.Collections.Generic;

using Xunit;

public class QueryParamsTest
{
    [Fact]
    public void Simple()
    {
        var parameters = new Dictionary<string, string>
            {
                {"username", "root"},
                {"realname", "First Last"},
            };
        var expected = "realname=First%20Last&username=root";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void ZeroParams()
    {
        var parameters = new Dictionary<string, string>();
        Assert.Equal("", DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void OneParam()
    {
        var parameters = new Dictionary<string, string>
            {
                {"realname", "First Last"},
            };
        var expected = "realname=First%20Last";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void PrintableASCII()
    {
        var parameters = new Dictionary<string, string>
            {
                {"digits", "0123456789"},
                {"letters", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"},
                {"punctuation", "!\"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~"},
                {"whitespace", "\t\n\u000b\u000c\r "},
        };
        var expected = "digits=0123456789&letters=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ&punctuation=%21%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F%3A%3B%3C%3D%3E%3F%40%5B%5C%5D%5E_%60%7B%7C%7D~&whitespace=%09%0A%0B%0C%0D%20";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void UnicodeFuzzValues()
    {
        var parameters = new Dictionary<string, string>
            {
                {"bar", "\u2815\uaaa3\u37cf\u4bb7\u36e9\ucc05\u668e\u8162\uc2bd\ua1f1"},
                {"baz", "\u0df3\u84bd\u5669\u9985\ub8a4\uac3a\u7be7\u6f69\u934a\ub91c"},
                {"foo", "\ud4ce\ud6d6\u7938\u50c0\u8a20\u8f15\ufd0b\u8024\u5cb3\uc655"},
                {"qux", "\u8b97\uc846-\u828e\u831a\uccca\ua2d4\u8c3e\ub8b2\u99be"},
            };
        var expected = "bar=%E2%A0%95%EA%AA%A3%E3%9F%8F%E4%AE%B7%E3%9B%A9%EC%B0%85%E6%9A%8E%E8%85%A2%EC%8A%BD%EA%87%B1&baz=%E0%B7%B3%E8%92%BD%E5%99%A9%E9%A6%85%EB%A2%A4%EA%B0%BA%E7%AF%A7%E6%BD%A9%E9%8D%8A%EB%A4%9C&foo=%ED%93%8E%ED%9B%96%E7%A4%B8%E5%83%80%E8%A8%A0%E8%BC%95%EF%B4%8B%E8%80%A4%E5%B2%B3%EC%99%95&qux=%E8%AE%97%EC%A1%86-%E8%8A%8E%E8%8C%9A%EC%B3%8A%EA%8B%94%E8%B0%BE%EB%A2%B2%E9%A6%BE";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void UnicodeFuzzKeysAndValues()
    {
        var parameters = new Dictionary<string, string>
            {
                {"\u469a\u287b\u35d0\u8ef3\u6727\u502a\u0810\ud091\xc8\uc170", "\u0f45\u1a76\u341a\u654c\uc23f\u9b09\uabe2\u8343\u1b27\u60d0"},
                {"\u7449\u7e4b\uccfb\u59ff\ufe5f\u83b7\uadcc\u900c\ucfd1\u7813", "\u8db7\u5022\u92d3\u42ef\u207d\u8730\uacfe\u5617\u0946\u4e30"},
                {"\u7470\u9314\u901c\u9eae\u40d8\u4201\u82d8\u8c70\u1d31\ua042", "\u17d9\u0ba8\u9358\uaadf\ua42a\u48be\ufb96\u6fe9\ub7ff\u32f3"},
                {"\uc2c5\u2c1d\u2620\u3617\u96b3F\u8605\u20e8\uac21\u5934", "\ufba9\u41aa\ubd83\u840b\u2615\u3e6e\u652d\ua8b5\ud56bU"},
            };
        var expected = "%E4%9A%9A%E2%A1%BB%E3%97%90%E8%BB%B3%E6%9C%A7%E5%80%AA%E0%A0%90%ED%82%91%C3%88%EC%85%B0=%E0%BD%85%E1%A9%B6%E3%90%9A%E6%95%8C%EC%88%BF%E9%AC%89%EA%AF%A2%E8%8D%83%E1%AC%A7%E6%83%90&%E7%91%89%E7%B9%8B%EC%B3%BB%E5%A7%BF%EF%B9%9F%E8%8E%B7%EA%B7%8C%E9%80%8C%EC%BF%91%E7%A0%93=%E8%B6%B7%E5%80%A2%E9%8B%93%E4%8B%AF%E2%81%BD%E8%9C%B0%EA%B3%BE%E5%98%97%E0%A5%86%E4%B8%B0&%E7%91%B0%E9%8C%94%E9%80%9C%E9%BA%AE%E4%83%98%E4%88%81%E8%8B%98%E8%B1%B0%E1%B4%B1%EA%81%82=%E1%9F%99%E0%AE%A8%E9%8D%98%EA%AB%9F%EA%90%AA%E4%A2%BE%EF%AE%96%E6%BF%A9%EB%9F%BF%E3%8B%B3&%EC%8B%85%E2%B0%9D%E2%98%A0%E3%98%97%E9%9A%B3F%E8%98%85%E2%83%A8%EA%B0%A1%E5%A4%B4=%EF%AE%A9%E4%86%AA%EB%B6%83%E8%90%8B%E2%98%95%E3%B9%AE%E6%94%AD%EA%A2%B5%ED%95%ABU";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void SortOrderWithCommonPrefix()
    {
        var parameters = new Dictionary<string, string>
            {
                {"foo_bar", "2"},
                {"foo", "1"},
            };
        var expected = "foo=1&foo_bar=2";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }

    [Fact]
    public void NextOffsetTest()
    {
        string[] offset = new string[] { "fjaewoifjew", "473891274832917498" };
        var parameters = new Dictionary<string, object>
            {
                {"next_offset", offset},
                {"foo", "1"},
            };
        var expected = "foo=1&next_offset=fjaewoifjew&next_offset=473891274832917498";
        Assert.Equal(expected, DuoApi.CanonicalizeParams(parameters));
    }
}