/*
 * Copyright (c) 2026 Cisco Systems, Inc. and/or its affiliates
 * All rights reserved
 */

using System;
using System.Security.Cryptography;

namespace Duo
{
    /// <summary>
    /// Helpers for pinning on the Subject Public Key Info (SPKI) of a certificate
    /// rather than on the certificate's full DER encoding.
    ///
    /// Pinning on the SPKI (SHA-256 of the DER-encoded SubjectPublicKeyInfo) is
    /// robust against cross-signing: the self-signed and cross-signed forms of the
    /// same CA share an identical public key, so they produce the same SPKI hash
    /// even though their full certificate DER differs (different issuer, different
    /// signature). This is the pin format described by RFC 7469 (HPKP).
    ///
    /// <see cref="System.Security.Cryptography.X509Certificates.PublicKey.ExportSubjectPublicKeyInfo"/>
    /// only exists on .NET 6+, so on the frameworks this library targets the SPKI
    /// bytes are extracted by parsing the certificate DER directly.
    /// </summary>
    internal static class SpkiPinning
    {
        /// <summary>
        /// Compute the base64-encoded SHA-256 hash of a certificate's
        /// SubjectPublicKeyInfo, given the raw DER bytes of the certificate.
        /// </summary>
        internal static string ComputeSpkiSha256(byte[] rawCertData)
        {
            byte[] spki = ExtractSubjectPublicKeyInfo(rawCertData);
            using (var sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(spki));
            }
        }

        /// <summary>
        /// Extract the DER-encoded SubjectPublicKeyInfo (the full TLV, including the
        /// outer SEQUENCE tag and length) from a DER-encoded X.509 certificate.
        ///
        /// This copies the bytes that are already present in the certificate rather
        /// than reconstructing them, so it is byte-for-byte correct and agnostic to
        /// the key algorithm (RSA, EC, ...).
        ///
        /// X.509 structure walked here (RFC 5280):
        ///   Certificate ::= SEQUENCE {
        ///       tbsCertificate       TBSCertificate,
        ///       signatureAlgorithm   ...,
        ///       signatureValue       ... }
        ///   TBSCertificate ::= SEQUENCE {
        ///       [0] version           -- optional, EXPLICIT context tag 0xA0
        ///       serialNumber,
        ///       signature,
        ///       issuer,
        ///       validity,
        ///       subject,
        ///       subjectPublicKeyInfo, -- what we want
        ///       ... }
        /// </summary>
        internal static byte[] ExtractSubjectPublicKeyInfo(byte[] cert)
        {
            if (cert == null || cert.Length == 0)
            {
                throw new CryptographicException("Empty certificate data; cannot extract SubjectPublicKeyInfo.");
            }

            int index = 0;

            // Descend into Certificate ::= SEQUENCE
            EnterSequence(cert, ref index);
            // Descend into tbsCertificate ::= SEQUENCE
            EnterSequence(cert, ref index);

            // Skip the optional EXPLICIT [0] version field, if present.
            if (index < cert.Length && cert[index] == 0xA0)
            {
                SkipField(cert, ref index);
            }

            // Skip serialNumber, signature, issuer, validity, subject (5 fields).
            for (int i = 0; i < 5; i++)
            {
                SkipField(cert, ref index);
            }

            // The next field is subjectPublicKeyInfo. Copy its complete TLV.
            int spkiStart = index;
            SkipField(cert, ref index);
            int spkiLength = index - spkiStart;

            byte[] spki = new byte[spkiLength];
            Buffer.BlockCopy(cert, spkiStart, spki, 0, spkiLength);
            return spki;
        }

        /// <summary>
        /// Verify the tag at <paramref name="index"/> is a DER SEQUENCE (0x30) and
        /// advance <paramref name="index"/> to the first byte of its content, so the
        /// caller can walk the sequence's members.
        /// </summary>
        private static void EnterSequence(byte[] data, ref int index)
        {
            if (index >= data.Length || data[index] != 0x30)
            {
                throw new CryptographicException("Malformed certificate: expected a DER SEQUENCE.");
            }
            index++;
            ReadLength(data, ref index);
        }

        /// <summary>
        /// Advance <paramref name="index"/> past one complete DER TLV (tag, length,
        /// and content). Certificate fields use single-byte tags, so no high-tag-number
        /// handling is required.
        /// </summary>
        private static void SkipField(byte[] data, ref int index)
        {
            if (index >= data.Length)
            {
                throw new CryptographicException("Malformed certificate: unexpected end of data.");
            }
            index++; // tag
            int length = ReadLength(data, ref index);
            index += length; // content
            if (index > data.Length)
            {
                throw new CryptographicException("Malformed certificate: field length exceeds data.");
            }
        }

        /// <summary>
        /// Read a DER length at <paramref name="index"/>, advancing <paramref name="index"/>
        /// past the length bytes. Supports the short form and the definite long form.
        /// </summary>
        private static int ReadLength(byte[] data, ref int index)
        {
            if (index >= data.Length)
            {
                throw new CryptographicException("Malformed certificate: unexpected end of data reading length.");
            }

            int first = data[index++];
            if (first < 0x80)
            {
                // Short form: length is the byte itself.
                return first;
            }

            int numBytes = first & 0x7F;
            // 0x80 (indefinite form) is not valid in DER; more than 4 length bytes
            // would overflow an int and is far larger than any real certificate.
            if (numBytes == 0 || numBytes > 4)
            {
                throw new CryptographicException("Malformed certificate: unsupported DER length encoding.");
            }

            int length = 0;
            for (int i = 0; i < numBytes; i++)
            {
                if (index >= data.Length)
                {
                    throw new CryptographicException("Malformed certificate: unexpected end of data reading length.");
                }
                length = (length << 8) | data[index++];
            }

            if (length < 0)
            {
                throw new CryptographicException("Malformed certificate: negative DER length.");
            }
            return length;
        }
    }
}
