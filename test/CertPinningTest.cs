/*
 * Copyright (c) 2022 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using Duo;
using System;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Xunit;

public class CertPinningTestBase
{
    // Helper methods and some hard-coded certificates
    protected static X509Certificate2 DuoApiServerCert()
    {
        // The leaf certificate for api-*.duosecurity.com
        return CertFromString(DUO_API_CERT_SERVER);
    }

    protected static X509Chain DuoApiChain()
    {
        // The certificate chain for api-*.duosecurity.com
        var chain = new X509Chain();
        // Verify as of a date that the certs are valid for
        chain.ChainPolicy.VerificationTime = new DateTime(2024, 12, 06);
        chain.ChainPolicy.ExtraStore.Add(CertFromString(DUO_API_CERT_ROOT));
        chain.ChainPolicy.ExtraStore.Add(CertFromString(DUO_API_CERT_INTER));
        bool valid = chain.Build(DuoApiServerCert());
        Assert.True(valid);
        return chain;
    }

    protected static X509Chain MicrosoftComChain()
    {
        // A valid chain, but for www.microsoft.com, not Duo
        var chain = new X509Chain();
        // Verify as of a date that the certs are valid for
        chain.ChainPolicy.VerificationTime = new DateTime(2024, 12, 06);
        chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_ROOT));
        chain.ChainPolicy.ExtraStore.Add(CertFromString(MICROSOFT_COM_CERT_INTER));
        bool valid = chain.Build(CertFromString(MICROSOFT_COM_CERT_SERVER));
        Assert.True(valid);
        return chain;
    }

    protected static X509Certificate2 CertFromString(string certString)
    {
        return new X509Certificate2(Convert.FromBase64String(certString));
    }

    // Certificates exported from the web site 2024-12-06
    protected const string DUO_API_CERT_SERVER = "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";
    protected const string DUO_API_CERT_INTER = "MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3VyYW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC24C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMICKq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0Xsh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcftbZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwNAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIGBFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7DaQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwdaOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNHE+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zuxICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0AecPUeybQ=";
    protected const string DUO_API_CERT_ROOT = "MIIDxTCCAq2gAwIBAgIQAqxcJmoLQJuPC3nyrkYldzANBgkqhkiG9w0BAQUFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTA2MTExMDAwMDAwMFoXDTMxMTExMDAwMDAwMFowbDELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTErMCkGA1UEAxMiRGlnaUNlcnQgSGlnaCBBc3N1cmFuY2UgRVYgUm9vdCBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMbM5XPm+9S75S0tMqbf5YE/yc0lSbZxKsPVlDRnogocsF9ppkCxxLeyj9CYpKlBWTrT3JTWPNt0OKRKzE0lgvdKpVMSOO7zSW1xkX5jtqumX8OkhPhPYlG++MXs2ziS4wblCJEMxChBVfvLWokVfnHoNb9Ncgk9vjo4UFt3MRuNs8ckRZqnrG0AFFoEt7oT61EKmEFBIk5lYYeBQVCmeVyJ3hlKV9Uu5l0cUyx+mM0aBhakaHPQNAQTXKFx01p8VdteZOE3hzBWBOURtCmAEvF5OYiiAhF8J2a3iLd48soKqDirCmTCv2ZdlYTBoSUeh10aUAsgEsxBu24LUTi4S8sCAwEAAaNjMGEwDgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFLE+w2kD+L9HAdSYJhoIAu9jZCvDMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA0GCSqGSIb3DQEBBQUAA4IBAQAcGgaX3NecnzyIZgYIVyHbIUf4KmeqvxgydkAQV8GK83rZEWWONfqe/EW1ntlMMUu4kehDLI6zeM7b41N5cdblIZQB2lWHmiRk9opmzN6cN82oNLFpmyPInngiK3BD41VHMWEZ71jFhS9OMPagMRYjyOfiZRYzy78aG6A9+MpeizGLYAiJLQwGXFK3xPkKmNEVX58Svnw2Yzi9RKR/5CYrCsSXaQ3pjOLAEFe4yHYSkVXySGnYvCoCWw9E1CAx2/S6cCZdkGCevEsXCS+0yx5DaMkHJ8HSXPfqIbloEpw8nL+e/IBcm2PN7EeqJSdnoDfzAIJ9VNep+OkuE6N36B9K";

    // Certificates exported from the web sites 2024-12-06
    protected const string MICROSOFT_COM_CERT_SERVER = "MIII5jCCBs6gAwIBAgITMwCfe3NNsEgEEesLugAAAJ97czANBgkqhkiG9w0BAQwFADBdMQswCQYDVQQGEwJVUzEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMS4wLAYDVQQDEyVNaWNyb3NvZnQgQXp1cmUgUlNBIFRMUyBJc3N1aW5nIENBIDA0MB4XDTI0MDgyNjE2MDEwNloXDTI1MDgyMTE2MDEwNlowaDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xGjAYBgNVBAMTEXd3dy5taWNyb3NvZnQuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjDZqm36zWdsIRqHOOSfl90WMM0ZBogor9FVXqwkmbu5LBp/SXCIEMvG/AKIbJoAaiW4TXNXx1m7lY8UOuVXCz+PI6tAbpMEK1grsDCG9g4wrEyEcrnlHNFM2HszZl6Eb9wGpRXRPHDZjmL4J8LJnD/FEAmUmqApcv6oAU/VirWrDLwd63UTYp0FvdXGXKsrcvAuY0P/goxeXY6/QPWEGRNoBdlyojpNEUkOmf4CUDFuStK7owXJe6GKWOMDgxi/87h1ndL+gyE3amFIi05xszpgu1gOowrGxCPp21SrK6UK6yitsoJ/+vMpEjEfEZvmOrn3jAaeh342u2KlzKTKgwQIDAQABo4IEkjCCBI4wggF/BgorBgEEAdZ5AgQCBIIBbwSCAWsBaQB2AN3cyjSV1+EWBeeVMvrHn/g9HFDf2wA6FBJ2Ciysu8gqAAABkY90nU4AAAQDAEcwRQIhAORlhZnLcoCuh3SNvk+CpnAZobHFpYP76/HGOwoMv+zoAiB/MJTMBYvvOA/ZnXh9MZFyyOeMSseYWWlVS8w4qrNRmwB3AH1ZHhLheCp7HGFnfF79+NCHXBSgTpWeuQMv2Q6MLnm4AAABkY90nQAAAAQDAEgwRgIhAJ/rp9df4ATIIy5AIGJgk0BibLOve4dEPAwt2mZM8nIRAiEAmskJ7XyWHTb9sYKnclF56SDDSBjlp5+bwAXhLuQROjIAdgAaBP9J0FQdQK/2oMO/8djEZy9O7O4jQGiYaxdALtyJfQAAAZGPdJ1pAAAEAwBHMEUCIBisJvPWEDA1neKh8Yn1U5+yvezVoTz1sMYqkVWKYzMrAiEAxtg06KBLLOsqj9038NGT32WtDH6j1iq11D5M+Zm32GIwJwYJKwYBBAGCNxUKBBowGDAKBggrBgEFBQcDAjAKBggrBgEFBQcDATA8BgkrBgEEAYI3FQcELzAtBiUrBgEEAYI3FQiHvdcbgefrRoKBnS6O0AyH8NodXYKE5WmC86c+AgFkAgEmMIG0BggrBgEFBQcBAQSBpzCBpDBzBggrBgEFBQcwAoZnaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraW9wcy9jZXJ0cy9NaWNyb3NvZnQlMjBBenVyZSUyMFJTQSUyMFRMUyUyMElzc3VpbmclMjBDQSUyMDA0JTIwLSUyMHhzaWduLmNydDAtBggrBgEFBQcwAYYhaHR0cDovL29uZW9jc3AubWljcm9zb2Z0LmNvbS9vY3NwMB0GA1UdDgQWBBQKJ8rdkGFSE7iygWBQjsxBvS9NfjAOBgNVHQ8BAf8EBAMCBaAwgZkGA1UdEQSBkTCBjoITd3d3cWEubWljcm9zb2Z0LmNvbYIRd3d3Lm1pY3Jvc29mdC5jb22CGHN0YXRpY3ZpZXcubWljcm9zb2Z0LmNvbYIRaS5zLW1pY3Jvc29mdC5jb22CDW1pY3Jvc29mdC5jb22CEWMucy1taWNyb3NvZnQuY29tghVwcml2YWN5Lm1pY3Jvc29mdC5jb20wDAYDVR0TAQH/BAIwADBqBgNVHR8EYzBhMF+gXaBbhllodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBBenVyZSUyMFJTQSUyMFRMUyUyMElzc3VpbmclMjBDQSUyMDA0LmNybDBmBgNVHSAEXzBdMFEGDCsGAQQBgjdMg30BATBBMD8GCCsGAQUFBwIBFjNodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL0RvY3MvUmVwb3NpdG9yeS5odG0wCAYGZ4EMAQICMB8GA1UdIwQYMBaAFDtw0VPpdiWdYKjKZg/Gm65vVBZqMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDATANBgkqhkiG9w0BAQwFAAOCAgEAmT3I6UldBETIfNlm0VnZpY5avKJpEDYLYyC6S8J4JAqW8JhM4MloEfCxoAVf57rz/j+DkbZjn7iWUeuKtgMROi8u2hLG69TTw39kjx4L5tso139VLZVRFWsNpr70hqE7cUZT63CQQAM3Je4jrb3AhQyFZpnS7Fxqx7gJ3vIS9xJCkuTnTXeoJUJ5ESS/DQaRv4DleEa5qe6Wa+1fKP9Zsea4kiUVjP/vA5Bf2CzKapI7BkuyM/9MojV0djt98v21f4eLxJYvjqdtKP6lXkzRxKYde5BwF2w87z5AqTNx6/23ZJl1McJ/xmJLF+7tm1krBM/arTPJFJZKqZO8W/MApwLPRQJM7irXcUxq3LuXBhEINnYwZv6RhDlZ73yx/nhBAdu1LRnjfx71ecWBhtIc/SXw1xtbJV8EmHu6J5uNkM0PCLO91bRw/97zTdm32G9rNCHHCaq2iilQ3C4kL8r4krcYQPYWg3HpUqiqXV3Q9IPX2J1AxXP02UuI6Z7oIL4IiBzR80h+ng4Uwv+uQtp4VeVlJ9jvg+2G847+WxvW9Unw7Ca3Rvo/CKvSokQx+OsXu4g442p4bAUZObeohUZV++DwWpCKnJbnSykrv++yQ5NZm4mu8WyQseKNZGTtB4LtfR9gYPimDscQfjXPdTPBo88HFSI1Pkjwo6/Q0KXEF2A=";
    protected const string MICROSOFT_COM_CERT_INTER = "MIIFrDCCBJSgAwIBAgIQCfluwpVVXyR0nq8eXc7UnTANBgkqhkiG9w0BAQwFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0yMzA2MDgwMDAwMDBaFw0yNjA4MjUyMzU5NTlaMF0xCzAJBgNVBAYTAlVTMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xLjAsBgNVBAMTJU1pY3Jvc29mdCBBenVyZSBSU0EgVExTIElzc3VpbmcgQ0EgMDQwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDBeUy13eRZ/QC5bN7/IOGxodny7Xm2BFc88d3cca3yHyyVx1Y60+afY6DAo/2Ls1uzAfbDfMzAVWJazPH4tckaItDv//htEbbNJnAGvZPB4VqNviwDEmlAWT/MTAmzXfTgWXuUNgRlzZbjoFaPm+t6iJ6HdvDpWQAJbsBUZCgat257tM28JnAHUTWdiDBn+2z6EGh2DA6BCx04zHDKVSegLY8+5P80Lqze0d6i3T2JJ7rfxCmxUXfCGOv9iQIUZfhv4vCb8hsm/JdNUMiomJhSPa0bi3rda/swuJHCH//dwz2AGzZRRGdj7Kna4t6ToxK17lAF3Q6Qp368C9cE6JLMj+3UbY3umWCPRA5/Dms4/wl3GvDEw7HpyKsvRNPpjDZyiFzZGC2HZmGMsrZMT3hxmyQwmz1O3eGYdO5EIq1SW/vT1yShZTSusqmICQo5gWWRZTwCENekSbVX9qRr77o0pjKtuBMZTGQTixwpT/rgUl7Mr4M2nqK55Kovy/kUN1znfPdW/Fj9iCuvPKwKFdyt2RVgxJDvgIF/bNoRkRxhwVB6qRgs4EiTrNbRoZAHEFF5wRBf9gWn9HeoI66VtdMZvJRH+0/FDWB4/zwxS16nnADJaVPXh6JHJFYs9p0wZmvct3GNdWrOLRAG2yzbfFZS8fJcX1PYxXXo4By16yGWhQIDAQABo4IBYjCCAV4wEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUO3DRU+l2JZ1gqMpmD8abrm9UFmowHwYDVR0jBBgwFoAUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDgYDVR0PAQH/BAQDAgGGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjB2BggrBgEFBQcBAQRqMGgwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBABggrBgEFBQcwAoY0aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0R2xvYmFsUm9vdEcyLmNydDBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290RzIuY3JsMB0GA1UdIAQWMBQwCAYGZ4EMAQIBMAgGBmeBDAECAjANBgkqhkiG9w0BAQwFAAOCAQEAo9sJvBNLQSJ1e7VaG3cSZHBz6zjS70A1gVO1pqsmX34BWDPz1TAlOyJiLlA+eUF4B2OWHd3F//dJJ/3TaCFunjBhZudv3busl7flz42K/BG/eOdlg0kiUf07PCYY5/FKYTIch51j1moFlBqbglwkdNIVae2tOu0OdX2JiA+bprYcGxa7eayLetvPiA77ynTcUNMKOqYB41FZHOXe5IXDI5t2RsDM9dMEZv4+cOb9G9qXcgDar1AzPHEt/39335zCHofQ0QuItCDCDzahWZci9Nn9hb/SvAtPWHZLkLBG6I0iwGxvMwcTTc9Jnb4FlysrmQlwKsS2MphOoI23Qq3cSA==";
    protected const string MICROSOFT_COM_CERT_ROOT = "MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBhMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMTF0RpZ2lDZXJ0IEdsb2JhbCBSb290IEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuzfNNNx7a8myaJCtSnX/RrohCgiN9RlUyfuI2/Ou8jqJkTx65qsGGmvPrC3oXgkkRLpimn7Wo6h+4FR1IAWsULecYxpsMNzaHxmx1x7e/dfgy5SDN67sH0NO3Xss0r0upS/kqbitOtSZpLYl6ZtrAGCSYP9PIUkY92eQq2EGnI/yuum06ZIya7XzV+hdG82MHauVBJVJ8zUtluNJbd134/tJS7SsVQepj5WztCO7TG1F8PapspUwtP1MVYwnSlcUfIKdzXOS0xZKBgyMUNGPHgm+F6HmIcr9g+UQvIOlCsRnKPZzFBQ9RnbDhxSJITRNrw9FDKZJobq7nMWxM4MphQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUTiJUIBiV5uNu5g/6+rkS7QYXjzkwDQYJKoZIhvcNAQELBQADggEBAGBnKJRvDkhj6zHd6mcY1Yl9PMWLSn/pvtsrF9+wX3N3KjITOYFnQoQj8kVnNeyIv/iPsGEMNKSuIEyExtv4NeF22d+mQrvHRAiGfzZ0JFrabA0UWTW98kndth/Jsw1HKj2ZL7tcu7XUIOGZX1NGFdtom/DzMNU+MeKNhJ7jitralj41E6Vf8PlwUHBHQRFXGU7Aj64GxJUTFy8bJZ918rGOmaFvE7FBcf6IKshPECBV1/MUReXgRPTqh5Uykw7+U0b6LJ3/iyK5S9kJRaTepLiaWN0bfVKfjllDiIGknibVb63dDcY3fe0Dkhvld1927jyNxF1WW6LZZm6zNTflMrY=";
}

public class CertPinningTest : CertPinningTestBase
{

    private RemoteCertificateValidationCallback duoPinner;
    public CertPinningTest()
    {
        duoPinner = CertificatePinnerFactory.GetDuoCertificatePinner();
    }

    [Fact]
    public void TestReadCertFile()
    {
        Assert.Equal(15, CertificatePinnerFactory.ReadCertsFromFile().Length);
    }

    [Fact]
    public void TestSuccess()
    {
        Assert.True(duoPinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestNullCertificate()
    {
        Assert.False(duoPinner(null, null, DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestNullChain()
    {
        Assert.False(duoPinner(null, DuoApiServerCert(), null, SslPolicyErrors.None));
    }

    [Fact]
    public void TestFatalSslError()
    {
        Assert.False(duoPinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void TestUnmatchedRoot()
    {
        Assert.False(duoPinner(null, DuoApiServerCert(), MicrosoftComChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestAlternateCertsSuccess()
    {
        var certCollection = new X509Certificate2Collection
            {
                CertFromString(MICROSOFT_COM_CERT_ROOT)
            };

        var pinner = new CertificatePinnerFactory(certCollection).GetPinner();

        Assert.True(pinner(null, CertFromString(MICROSOFT_COM_CERT_SERVER), MicrosoftComChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestExpiredChainRejected()
    {
        // The OS rejected the chain, so it is validated against the bundle at the current
        // time, by which the 2024 leaf has expired.
        Assert.False(duoPinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestPinsOnIntermediateSpki()
    {
        // The pin may match anywhere in the validated chain, not just at the root, so
        // that a chain restructuring does not break the client.
        var intermediateOnly = new X509Certificate2Collection
            {
                CertFromString(DUO_API_CERT_INTER)
            };
        var pinner = new CertificatePinnerFactory(intermediateOnly).GetPinner();

        Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestPinsOnRootSpki()
    {
        // The contract the shipped bundle relies on: pinning the chain's root CA
        // accepts the chain.
        var rootOnly = new X509Certificate2Collection
            {
                CertFromString(DUO_API_CERT_ROOT)
            };
        var pinner = new CertificatePinnerFactory(rootOnly).GetPinner();

        Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestUnrelatedPinnedKeyRejected()
    {
        // Pinning a key that appears nowhere in the presented chain must reject the
        // connection, even though the OS validated the chain.
        var unrelated = new X509Certificate2Collection
            {
                CertFromString(MICROSOFT_COM_CERT_ROOT)
            };
        var pinner = new CertificatePinnerFactory(unrelated).GetPinner();

        Assert.False(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }
}

public class BundleAnchoredPinningTest : CertPinningTestBase
{
    // The certificates api-*.duosecurity.com sent on 2026-10-07: the leaf, its issuing CA,
    // and DigiCert TLS RSA4096 Root G5 cross-signed by DigiCert High Assurance EV Root CA.
    // As is normal for TLS, no root certificate is sent.
    private static readonly DateTime DuoChain2026Time = new DateTime(2026, 10, 7);
    private const string DUO_API_2026_CERT_SERVER = "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";
    private const string DUO_API_2026_CERT_INTER = "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";
    private const string DUO_API_2026_CERT_G5_CROSS = "MIIFizCCBHOgAwIBAgIQDmhhxVN+w8ZIHCtHCqtrLTANBgkqhkiG9w0BAQwFADBsMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5jZSBFViBSb290IENBMB4XDTIzMDUxMDAwMDAwMFoXDTMxMTEwOTIzNTk1OVowTTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMSUwIwYDVQQDExxEaWdpQ2VydCBUTFMgUlNBNDA5NiBSb290IEc1MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAs9D0yXkRnf38ZoHnzNXkvOyBPmo1ji63596v+QdNzzCd6gkLmb1sV9oYSrh4rDo5qKZIrC5y5b3r8RrN56QDqT8RtNgviRb7lAE9uy/4EwWheByOKOBF4IP0WRuVs65+A0XlvsJC/u7yPLaFE5gynRaoKcILHDjcnzF3XL8no/wnrLcrvXSbFy3ygdpdsOEjFz6IShIj0OrPnd4DF7FCSqAWTKRtk+k/Ou46fJ1YnfROj/w7I8htuOIF2szr7MMx9NenKVSAz0RbTG8wnvPM3R+UQ51Nf3BwDdQ60TfwbJ2bwBSTWO/NQTh1vBMDlXx/41zp1Q3V4nwQYqpr8D128z+j6LDB/e+qV02shqcYtCnBLA6/ZL4pjNgCLc1cL/J/7xX0DBWsCrDx0w1Pak13lwGg8Wa3t87vzuzspXXKrOPhY/e4oQTIvHs/XS0WIlbtSEn+py95MCWbumstP507xBfnHS778s+m/OMULJaYIYy0kekZYIPyMCsGc1DVmDsG6ceKDGCMKPhSm27h9k27BiSb1ysmP/0qL3H11iS+fzGeD23oj09Noz//NerfSV5Bj4b58Xd5Sxu0o14v+0YC0GYTXl6FT87YcIh7zgG1lpfXzX39gvjCJMHKATlPjaLBFEAfnGbVDAlG1vLQ0Uh2VjpDy7YKETm6jBNsBrWez+sCAwEAAaOCAUYwggFCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFFEzHO02QK8X0yXNaWjyr04jPrNBMB8GA1UdIwQYMBaAFLE+w2kD+L9HAdSYJhoIAu9jZCvDMA4GA1UdDwEB/wQEAwIBhjB/BggrBgEFBQcBAQRzMHEwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBJBggrBgEFBQcwAoY9aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNydDBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRIaWdoQXNzdXJhbmNlRVZSb290Q0EuY3JsMBEGA1UdIAQKMAgwBgYEVR0gADANBgkqhkiG9w0BAQwFAAOCAQEANTm3QDMNj87tEYmxMNE/4Z3xk5TaMhPYoRVQv2125QYhW6q9UMhapbtjtCRkaIt4JVEgnaAJ3UNZlWzVEuWIf69ttKPHm6+yCRIhxNxaKBcU8tJmf1lvyTEgPeNNskerPFZYV3enZu5fJydE5q91vtTFABYXUXt0CHAsqPrSLL2cY0wCqK1gKBnkerQT1o1COUbxIWCiIwAMRtyc+HLfs8cjupDnGookKJvH/RKAYqyz/zVjzPlm+n+e0/LRzjPB1s06H+c5AHy1wWxjJvrEB/JThp3hZkKaDiy4j1xSOFFJYUq6VT7VtpMaZ1pU/LUUiSPaMOj8zE/Nft1cR2jbhQ==";

    // The chain the platform hands the callback when the OS trust store lacks Duo's roots:
    // it can only be built as far as the certificates the server sent.
    private static X509Chain PresentedChain(X509Certificate2 leaf, DateTime verificationTime, params X509Certificate2[] sent)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationTime = verificationTime;
        foreach (var cert in sent)
        {
            chain.ChainPolicy.ExtraStore.Add(cert);
        }
        chain.Build(leaf);
        return chain;
    }

    private static X509Chain DuoApi2026PresentedChain()
    {
        return PresentedChain(CertFromString(DUO_API_2026_CERT_SERVER), DuoChain2026Time,
                              CertFromString(DUO_API_2026_CERT_INTER),
                              CertFromString(DUO_API_2026_CERT_G5_CROSS));
    }

    private static RemoteCertificateValidationCallback DuoPinnerAt(DateTime verificationTime)
    {
        return new CertificatePinnerFactory(CertificatePinnerFactory.GetDuoCertCollection(), verificationTime).GetPinner();
    }

    [Fact]
    public void TestDuoChainAcceptedWithoutOsTrust()
    {
        // The target scenario: the OS could not validate the chain, but it completes to a
        // certificate in the bundle.
        Assert.True(DuoPinnerAt(DuoChain2026Time)(null, CertFromString(DUO_API_2026_CERT_SERVER),
            DuoApi2026PresentedChain(), SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestDuoChainNameMismatchRejected()
    {
        Assert.False(DuoPinnerAt(DuoChain2026Time)(null, CertFromString(DUO_API_2026_CERT_SERVER),
            DuoApi2026PresentedChain(),
            SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void TestDuoChainExpiredRejected()
    {
        // The leaf expires 2027-03-08.
        Assert.False(DuoPinnerAt(new DateTime(2027, 4, 1))(null, CertFromString(DUO_API_2026_CERT_SERVER),
            DuoApi2026PresentedChain(), SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestDuoChainNotInBundleRejected()
    {
        var pinner = new CertificatePinnerFactory(
            new X509Certificate2Collection { CertFromString(MICROSOFT_COM_CERT_ROOT) }, DuoChain2026Time).GetPinner();

        Assert.False(pinner(null, CertFromString(DUO_API_2026_CERT_SERVER),
            DuoApi2026PresentedChain(), SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestDuo2024ChainAcceptedWithoutOsTrust()
    {
        // The older chain (leaf -> DigiCert SHA2 High Assurance Server CA -> High Assurance
        // EV Root CA), presented without its root.
        var time = new DateTime(2024, 12, 06);
        var chain = PresentedChain(DuoApiServerCert(), time, CertFromString(DUO_API_CERT_INTER));

        Assert.True(DuoPinnerAt(time)(null, DuoApiServerCert(), chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }
}

public class GeneratedChainPinningTest
{
    // These tests generate CAs at runtime, so no OS trust store contains them. The
    // certificates carry no AIA extension, so the platform cannot download anything:
    // whatever the chain reaches comes from what the server sent or from the anchors.

    private static readonly DateTimeOffset Now = DateTimeOffset.UtcNow;
    private const string ServerAuth = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuth = "1.3.6.1.5.5.7.3.2";

    private sealed class Ca
    {
        public X500DistinguishedName Name;
        public RSA Key;
        public X509Certificate2 Cert;
    }

    private static byte[] NewSerial()
    {
        var serial = new byte[8];
        new Random().NextBytes(serial);
        serial[0] &= 0x7F;
        return serial;
    }

    private static CertificateRequest CaRequest(X500DistinguishedName name, RSA key)
    {
        var req = new CertificateRequest(name, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        req.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    private static X509SignatureGenerator Signer(Ca issuer)
    {
        return X509SignatureGenerator.CreateForRSA(issuer.Key, RSASignaturePadding.Pkcs1);
    }

    private static Ca CreateRoot(string name, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        var ca = new Ca { Name = new X500DistinguishedName("CN=" + name), Key = RSA.Create(2048) };
        ca.Cert = CaRequest(ca.Name, ca.Key).CreateSelfSigned(notBefore, notAfter);
        return ca;
    }

    private static Ca CreateRoot(string name)
    {
        return CreateRoot(name, Now.AddDays(-60), Now.AddYears(1));
    }

    // A CA certificate for subject's name and key, signed by issuer. Used both for
    // intermediates and for cross-signing an existing root.
    private static X509Certificate2 CreateCaCert(Ca subject, Ca issuer, DateTimeOffset notBefore, DateTimeOffset notAfter)
    {
        return CaRequest(subject.Name, subject.Key).Create(issuer.Name, Signer(issuer), notBefore, notAfter, NewSerial());
    }

    private static Ca CreateIntermediate(string name, Ca issuer)
    {
        var ca = new Ca { Name = new X500DistinguishedName("CN=" + name), Key = RSA.Create(2048) };
        ca.Cert = CreateCaCert(ca, issuer, Now.AddDays(-30), Now.AddMonths(6));
        return ca;
    }

    private static X509Certificate2 CreateLeaf(Ca issuer, DateTimeOffset notBefore, DateTimeOffset notAfter, string eku = ServerAuth)
    {
        using (var key = RSA.Create(2048))
        {
            var req = new CertificateRequest("CN=api-test.duosecurity.com", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            req.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid(eku) }, false));
            return req.Create(issuer.Name, Signer(issuer), notBefore, notAfter, NewSerial());
        }
    }

    private static X509Certificate2 CreateLeaf(Ca issuer, string eku = ServerAuth)
    {
        return CreateLeaf(issuer, Now.AddDays(-1), Now.AddDays(30), eku);
    }

    // The chain the platform hands the callback: built from what the server sent.
    private static X509Chain PresentedChain(X509Certificate2 leaf, params X509Certificate2[] sent)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        foreach (var cert in sent)
        {
            chain.ChainPolicy.ExtraStore.Add(cert);
        }
        chain.Build(leaf);
        return chain;
    }

    private static RemoteCertificateValidationCallback PinnerFor(params X509Certificate2[] anchors)
    {
        return new CertificatePinnerFactory(new X509Certificate2Collection(anchors)).GetPinner();
    }

    // Duo's real chain shape: leaf -> intermediate -> new root cross-signed by an old root,
    // with no root sent. Only the old root is an anchor.
    private sealed class CrossSignedChain
    {
        public Ca OldRoot;
        public Ca NewRoot;
        public X509Certificate2 NewRootCross;
        public Ca Intermediate;
        public X509Certificate2 Leaf;
    }

    private static CrossSignedChain CreateCrossSignedChain()
    {
        var c = new CrossSignedChain();
        c.OldRoot = CreateRoot("Old Test Root");
        c.NewRoot = CreateRoot("New Test Root");
        c.NewRootCross = CreateCaCert(c.NewRoot, c.OldRoot, Now.AddDays(-30), Now.AddMonths(9));
        c.Intermediate = CreateIntermediate("Test Issuing CA", c.NewRoot);
        c.Leaf = CreateLeaf(c.Intermediate);
        return c;
    }

    [Fact]
    public void TestCrossSignedChainAccepted()
    {
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.True(PinnerFor(c.OldRoot.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestAnchorOnSelfSignedFormAccepted()
    {
        // Anchoring on the self-signed form of the cross-signed root also completes the chain.
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.True(PinnerFor(c.NewRoot.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestPartialChainRejected()
    {
        // The server omits the intermediate, so the chain cannot reach the anchor.
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.NewRootCross);

        Assert.False(PinnerFor(c.OldRoot.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestPinnedIntermediateNotAnAnchor()
    {
        // An anchor must end the chain. An intermediate whose issuer is unavailable leaves a
        // PartialChain, which is rejected.
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.False(PinnerFor(c.Intermediate.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestNameMismatchRejected()
    {
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.False(PinnerFor(c.OldRoot.Cert)(null, c.Leaf, chain,
            SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(PinnerFor(c.OldRoot.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void TestCertificateNotAvailableRejected()
    {
        var c = CreateCrossSignedChain();
        var chain = PresentedChain(c.Leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.False(PinnerFor(c.OldRoot.Cert)(null, c.Leaf, chain, SslPolicyErrors.RemoteCertificateNotAvailable));
    }

    [Fact]
    public void TestUnbundledRootRejected()
    {
        // The server sends its own self-signed root, which is not an anchor.
        var anchor = CreateRoot("Pinned Test Root");
        var other = CreateRoot("Unpinned Test Root");
        var leaf = CreateLeaf(other);
        var chain = PresentedChain(leaf, other.Cert);

        Assert.False(PinnerFor(anchor.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(CertificatePinnerFactory.GetDuoCertificatePinner()(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestRewrappedPinnedKeyRejected()
    {
        // The pinned root has expired. An attacker who obtained a leaf signed by the pinned
        // key re-wraps that key in an unexpired CA certificate issued by their own root. The
        // chain then contains the pinned key (an SPKI match), but it does not end at the
        // pinned certificate, so the real certificate's validity cannot be bypassed.
        var pinned = CreateRoot("Pinned Test Root", Now.AddYears(-2), Now.AddDays(-1));
        var attacker = CreateRoot("Attacker Root");
        var rewrapped = CreateCaCert(pinned, attacker, Now.AddDays(-30), Now.AddMonths(6));
        var leaf = CreateLeaf(pinned);
        var chain = PresentedChain(leaf, rewrapped, attacker.Cert);

        Assert.False(PinnerFor(pinned.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestExpiredLeafRejected()
    {
        var root = CreateRoot("Pinned Test Root");
        var leaf = CreateLeaf(root, Now.AddDays(-30), Now.AddDays(-1));
        var chain = PresentedChain(leaf);

        Assert.False(PinnerFor(root.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestExpiredIntermediateRejected()
    {
        var root = CreateRoot("Pinned Test Root");
        var intermediate = new Ca { Name = new X500DistinguishedName("CN=Test Issuing CA"), Key = RSA.Create(2048) };
        intermediate.Cert = CreateCaCert(intermediate, root, Now.AddDays(-30), Now.AddDays(-1));
        var leaf = CreateLeaf(intermediate);
        var chain = PresentedChain(leaf, intermediate.Cert);

        Assert.False(PinnerFor(root.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestMissingServerAuthEkuRejected()
    {
        var c = CreateCrossSignedChain();
        var leaf = CreateLeaf(c.Intermediate, ClientAuth);
        var chain = PresentedChain(leaf, c.Intermediate.Cert, c.NewRootCross);

        Assert.False(PinnerFor(c.OldRoot.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestForgedIssuerRejected()
    {
        // An attacker CA with the same name as the pinned root: the leaf names the pinned
        // root as issuer but is not signed by its key.
        var root = CreateRoot("Pinned Test Root");
        var impostor = CreateRoot("Pinned Test Root");
        var leaf = CreateLeaf(impostor);
        var chain = PresentedChain(leaf);

        Assert.False(PinnerFor(root.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestNonCaIssuerRejected()
    {
        // An end-entity certificate under the pinned root must not be usable to issue certificates.
        var root = CreateRoot("Pinned Test Root");
        var notACa = new Ca { Name = new X500DistinguishedName("CN=Not A CA"), Key = RSA.Create(2048) };
        var req = new CertificateRequest(notACa.Name, notACa.Key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        notACa.Cert = req.Create(root.Name, Signer(root), Now.AddDays(-1), Now.AddDays(30), NewSerial());
        var leaf = CreateLeaf(notACa);
        var chain = PresentedChain(leaf, notACa.Cert);

        Assert.False(PinnerFor(root.Cert)(null, leaf, chain, SslPolicyErrors.RemoteCertificateChainErrors));
    }
}

public class SpkiPinningTest : CertPinningTestBase
{
    // SPKI SHA-256 hashes independently computed with:
    //   openssl x509 -noout -pubkey | openssl pkey -pubin -outform DER | sha256sum | base64
    private const string DUO_ROOT_SPKI = "WoiWRyIOVNa9ihaBciRSC7XHjliYS9VwUGOIud4PB18=";
    private const string DUO_INTER_SPKI = "k2v657xBsOVe1PQRwOsHsw3bsGT2VzIqz5K+59sNQws=";
    private const string MICROSOFT_ROOT_SPKI = "i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=";

    [Theory]
    [InlineData(DUO_API_CERT_ROOT, DUO_ROOT_SPKI)]
    [InlineData(DUO_API_CERT_INTER, DUO_INTER_SPKI)]
    [InlineData(MICROSOFT_COM_CERT_ROOT, MICROSOFT_ROOT_SPKI)]
    public void TestComputeSpkiSha256MatchesOpenSsl(string certBase64, string expectedSpki)
    {
        var cert = CertFromString(certBase64);
        Assert.Equal(expectedSpki, Duo.SpkiPinning.ComputeSpkiSha256(cert.RawData));
    }

    [Fact]
    public void TestSpkiHashIsDeterministic()
    {
        var root = CertFromString(DUO_API_CERT_ROOT);
        string first = Duo.SpkiPinning.ComputeSpkiSha256(root.RawData);
        string second = Duo.SpkiPinning.ComputeSpkiSha256(root.RawData);
        Assert.Equal(first, second);
        Assert.Equal(DUO_ROOT_SPKI, first);
    }

    [Fact]
    public void TestEmptyDataThrows()
    {
        Assert.ThrowsAny<Exception>(() => Duo.SpkiPinning.ComputeSpkiSha256(new byte[0]));
    }

    [Fact]
    public void TestAllBundledCertsHashable()
    {
        // Every certificate shipped in ca_certs.pem must be parseable by the SPKI
        // extractor (no malformed/unsupported DER in the bundle).
        var certs = CertificatePinnerFactory.GetDuoCertCollection();
        Assert.NotEmpty(certs);
        foreach (X509Certificate cert in certs)
        {
            var c2 = new X509Certificate2(cert);
            string hash = Duo.SpkiPinning.ComputeSpkiSha256(c2.RawData);
            Assert.False(string.IsNullOrEmpty(hash));
        }
    }
}

public class CertDisablingTest : CertPinningTestBase
{
    private RemoteCertificateValidationCallback pinner;

    public CertDisablingTest()
    {
        pinner = CertificatePinnerFactory.GetCertificateDisabler();
    }

    [Fact]
    public void TestSuccess()
    {
        Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestNullCertificate()
    {
        Assert.True(pinner(null, null, DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestNullChain()
    {
        Assert.True(pinner(null, DuoApiServerCert(), null, SslPolicyErrors.None));
    }

    [Fact]
    public void TestFatalSslError()
    {
        Assert.True(pinner(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void TestUnmatchedRoot()
    {
        Assert.True(pinner(null, DuoApiServerCert(), MicrosoftComChain(), SslPolicyErrors.None));
    }
}

public class OsTrustStoreValidatorTest : CertPinningTestBase
{
    private RemoteCertificateValidationCallback validator;

    public OsTrustStoreValidatorTest()
    {
        validator = CertificatePinnerFactory.GetOsTrustStoreValidator();
    }

    [Fact]
    public void TestSuccess()
    {
        // A chain that passed the platform's default validation is accepted,
        // even though it is not one of Duo's pinned roots.
        Assert.True(validator(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestUnpinnedRootAccepted()
    {
        // Pinning is disabled, so a valid non-Duo root (which the Duo pinner would
        // reject) is accepted as long as TLS validation itself succeeded.
        Assert.True(validator(null, CertFromString(MICROSOFT_COM_CERT_SERVER), MicrosoftComChain(), SslPolicyErrors.None));
    }

    [Fact]
    public void TestFatalSslError()
    {
        // TLS is still enforced: any SSL policy error rejects the connection.
        Assert.False(validator(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void TestChainErrorRejected()
    {
        Assert.False(validator(null, DuoApiServerCert(), DuoApiChain(), SslPolicyErrors.RemoteCertificateChainErrors));
    }

    [Fact]
    public void TestNoCertificateRejected()
    {
        Assert.False(validator(null, null, null, SslPolicyErrors.RemoteCertificateNotAvailable));
    }
}

public class DisableCaPinningConfigTest
{
    [Fact]
    public void TestCustomRootsWithPinningDisabledThrows()
    {
        var api = new DuoApi("ikey", "skey", "example.com", null).DisableCaPinning();
        var customRoots = new X509Certificate2Collection();

        Assert.Throws<InvalidOperationException>(() => api.UseCustomRootCertificates(customRoots));
    }

    [Fact]
    public void TestCustomRootsWithPinningEnabledSucceeds()
    {
        var api = new DuoApi("ikey", "skey", "example.com", null);
        var customRoots = new X509Certificate2Collection();

        // Should not throw and should return the client for chaining.
        Assert.Same(api, api.UseCustomRootCertificates(customRoots));
    }

    [Fact]
    public void TestDisableCaPinningReturnsClientForChaining()
    {
        var api = new DuoApi("ikey", "skey", "example.com", null);

        Assert.Same(api, api.DisableCaPinning());
    }
}
