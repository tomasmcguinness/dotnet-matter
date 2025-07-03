using Matter.Core;
using Matter.Core.Sessions;
using Matter.Core.TLV;
using Org.BouncyCastle.Math;

namespace Matter.Tests;

public class MatterTLVTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void MessageDecode()
    {
        var payload = "01-00-00-00-5A-D2-F8-02-00-00-00-00-00-00-00-00-04-21-E8-EF-00-00-15-30-01-20-A3-74-0F-F2-CD-24-67-C3-75-66-EA-7C-A3-B1-D0-04-3B-C8-88-F1-E7-2F-54-EB-A7-2B-54-58-D8-75-9D-10-30-02-20-AC-66-29-AC-EC-48-40-76-79-30-E5-FC-48-9B-75-E5-D2-93-2A-61-1C-6E-C9-C0-50-9E-1A-5A-D7-41-DA-C7-25-03-A2-35-35-04-25-01-E8-03-30-02-20-32-7F-9E-4B-E6-66-63-23-1B-FD-68-F1-7B-62-9B-43-E2-3B-22-D4-CF-32-2B-BF-5F-21-09-B3-F1-71-6A-60-18-35-05-25-01-F4-01-25-02-2C-01-25-03-A0-0F-24-04-13-24-05-0C-26-06-00-00-05-01-24-07-01-18-18";
        var payloadAsBytes = StringToByteArray(payload);

        var messageFrameParts = new MessageFrameParts(payloadAsBytes);
        var messagePayload = new MessagePayload(messageFrameParts.MessagePayload);
    }

    [Test]
    public void MessageDecode2()
    {
        var payload = "00-DA-2D-00-CD-7E-42-09-3A-39-8C-E1-F3-18-65-7F-75-67-95-BB-F4-79-2D-B4-2C-43-19-B5-3E-D6-35-45-B2-06-38-82-60-78-1F-3A-47-F4-74-80-58-0A-32-DC-72-A5-DC-62-8B-3E-9A-AA-FA-18-2F-30-24-43-BA-57-CE-2D-45-C2-FE-DC-43-7E-2E-E4-C3-AD-0E-37-5C-0C-24-C2-E8-DE-E2-27-41-A7-AD-BF-58-F9-9D-D7-9D-99-9C-4F-10-D2-EA-50-62-70-8D-B1-4B-9B-40-A9-6A-0F-DF-D2-42-11-EA-03-36-0A-8E-B6-0D-E9-CE-37-BE-4E-68-BC-19-EF-BB-C6-0A-16-3F-6F-E4-85-AC-D1-F7-83-F9-01-E2-1B-66-B0-5F-E2-BA-47-47-BF-E2-88-69-95-86-EE-41-1E-B5-D0-D4-D4-5C-1E-E7-E2-84-D6-11-7D-AD-7B-DD-B1-D5-92-0E-5B-B5-46-DD-29-34-B1-F2-CF-9D-FA-39-A4-FC-05-7C-C1-FF-A1-C8-E1-5A-05-E1-4D-BA-2E-EC-DD-5D-EB-10-F5-59-BA-FB-31-DE-0D-4F-7C-9B-E3-25-81-BE-08-53-C0-F1-02-AC-4D-2E-E7-19-E0-8C-68-49-0A-5D-DF-1D-28-B1-A7-7F-48-94-8D-39-92-4A-1B-4A-DF-8B-97-B5-01-AA-CC-C0-83-41-1B-AA-D2-42-28-BF-51-48-AE-5F-56-D4-4A-2E-4A-AD-14-8C-88-BA-8F-06-D1-62-1C-50-88-85-13-1C-59-48-1A-8C-FB-51-D5-CC-5E-E2-29-1D-F3-19-CE-2A-92-7E-E8-53-6B-2D-4B-51-70-53-1F-0F-5E-AE-8C-D7-72-81-1C-08-1C-0A-B6-B1-7F-8A-29-6E-5F-40-36-24-A9-EA-B0-A1-CC-6A-BE-4E-2C-E2-20-0A-3F-6E-CE-F8-EE-18-7D-5F-DD-5D-B4-0B-F9-1C-A1-5B-9B";
        var payloadAsBytes = StringToByteArray(payload);

        var messageFrameParts = new MessageFrameParts(payloadAsBytes);
        var messagePayload = new MessagePayload(messageFrameParts.MessagePayload);
    }

    [Test]
    public void MessageDecode3()
    {
        var payload = "00-79-21-00-76-D0-33-01-91-23-64-74-2D-9E-98-C0-41-38-EB-85-3F-F6-1A-B9-0C-39-2A-96-FB-52-4A-68-C5-6E";
        var payloadAsBytes = StringToByteArray(payload);

        var messageFrameParts = new MessageFrameParts(payloadAsBytes);
        var messagePayload = new MessagePayload(messageFrameParts.MessagePayload);
    }

    [Test]
    public void DecodeCertificatePayload()
    {
        var payload = "153001010024020137032414001826047634c72d2605f66a7442370624140018240701240801300941045f2fed6a8fccb5276a8880c140a408cd0e32b861a64868203ab1d305c26b42b073d5d3f582c12c5fa6bed8870c5a833d9cfa04fe635926f29b5dc5999e1dc399370a3501290118240260300414ecdc34bc8a9872984cb52a0aa526140a3af9bcb3300514ecdc34bc8a9872984cb52a0aa526140a3af9bcb318300b40cab8735099dc984c679af164ea3f28f96ea228bfb7a39bfa91a341af7ce733a63e1ffd797801f02f8c19124db5c3899a04557bcd412f1b0259fea9c36da19ebd18";
        var payloadAsBytes = StringToByteArray(payload);

        MatterTLV tlv = new MatterTLV(payloadAsBytes);

        Console.WriteLine(tlv.ToString());
    }

    [Test]
    public void Test()
    {
        var decryptKey = "B0-74-1E-81-B3-5B-A3-3E-08-B4-0F-CE-D2-FE-3A-BB";
        decryptKey = decryptKey.Replace("-", string.Empty);
        var encryptKey = "41-D8-F6-02-A9-D3-00-F7-BB-14-37-3D-2B-A0-8D-79";
        encryptKey = encryptKey.Replace("-", string.Empty);
        var sessionId = (ushort)63813;
        var session = new PaseSecureSession(new FakeConnection(), sessionId, StringToByteArray(encryptKey), StringToByteArray(decryptKey));

        var encryptedPayload = "01-C0-89-00-2F-23-16-03-00-00-00-00-00-00-00-00-5B-92-C7-29-67-75-BC-62-2E-F0-19-51-63-B7-CC-50-9B-4B-4F-4B-7A-40-DF-C7-5B-0C-3F-D2-6E-08-EA-36-9F-4B-E0-ED-FE-55-44-58-29-40-C7-4D-BA-A7-50-7E-AB-4D-D6-F5-04-E1-95-92-14-08-78-E3-6D-D6-33-EB-0F-82-1F-51-21-F3-87-C0-FC-26-BC-56-54-E3-18-A1-9C-36-7D-A9-F3-E1-3B-41-98-2F-11-D4-14-F2-63-E4-70-BD-A9-C2-41-E7-84-90-2F-C5-30-23-2D-07-6D-2D-6A-79-71-43-E8-47-02-25-B3-56-5A-6D-BC-36-0D-36-9C-66-3F-BF-9A-8F-13-F0-19-CA-86-FC-CF-F1-95-73-E5-DF-7D-7C-22-85-C9-19-B2-34-F2-0D-20-97-4F-A6-BC-29-4C-F0-9F-AC-92-91-7C-D0-39-FE-99-23-41-C5-58-CE-59-92-8D-EA-3C-04-02-F4-F4-CE-97-3A-F3-16-DF-E5-B0-3E-5C-87-0B-13-C0-AE-59-EB-E6-4E-DB-FB-19-52-4D-DE-07-FD-16-9D-9D-24-AA-09-2A-B1-DA-3E-62-01-35-97-38-6E-A6-12-1A-05-17-26-1C-52-82-F9-68-07-0E-E9-1F-7C-8D-E7-5A-86-8D-81-9A-21-C9-C1-50-AD-29-A9-27-25-5E-5E-34-76-BD-68-47-7B-BF-72-7A-B4-37-D5-68-E5-E7-15-29-B5-20-CB-E7-46-F1-F6-19-9C-EF-56-1D-26-E5-13-79-F1-63-48-B7-D6-0B-03-79-D9-3A-13-D4-FF-6D-BC-C5-CC-FC-B8-E3-CE-CE-3F-FD-F1-8C-18-95-AD-42-EA-B5-50-E1-6E-EF-B1-C7-6F-E0-7B-F4-5F-E3-ED-8E-16-50-1C-45-6C-49-9B-F4-F7-CD-BD-C8-0B-A2-D1-74-27-43-8A-11-0D-CE-77-7B-8A";

        encryptedPayload = encryptedPayload.Replace("-", string.Empty);

        var payloadAsBytes = StringToByteArray(encryptedPayload);

        var messageFrameParts = new MessageFrameParts(payloadAsBytes);

        var messageFrame = session.Decode(messageFrameParts);

        Assert.That(messageFrame.MessageFlags, Is.EqualTo(MessageFlags.DSIZ1));
        Assert.That(messageFrame.MessagePayload.ExchangeID, Is.EqualTo(2633));
        Assert.That(messageFrame.MessagePayload.ProtocolId, Is.EqualTo(0x01));
        Assert.That(messageFrame.MessagePayload.ProtocolOpCode, Is.EqualTo(0x09));
    }

    [Test]
    public void GenerateDebugOutput()
    {
        var reportDataPayload = "15-36-01-15-35-01-26-00-6B-65-DE-65-37-01-24-02-00-24-03-28-24-04-01-18-2C-02-0E-6D-61-74-74-65-72-2D-6E-6F-64-65-2E-6A-73-18-18-18-29-04-24-FF-0C-18";

        reportDataPayload = reportDataPayload.Replace("-", string.Empty);

        var payload = StringToByteArray(reportDataPayload);

        MatterTLV tlv = new MatterTLV(payload);

        Console.WriteLine(tlv.ToString());
    }

    [Test]
    public void GenerateDebugOutputForInvokeResponse()
    {
        var invokeResponsePayload = "1528003601153500370024000024013E2402051835013000F3153001CB3081C83070020100300E310C300A060355040A0C034353523059301306072A8648CE3D020106082A8648CE3D0301070342000477B1AB66DA2EE06065DE9D9E8EA4A4C067AA7061DFAD38991525F501B2BDFCCFCF1E00283F6FB5FFBCA052FC85D59430BF4E9D5111EC0B5098680F737EECF526A000300A06082A8648CE3D0403020348003045022100D1E124D12CA7837D3C40F7AED9B18D1BF29FA6BC1F19A6AAE53678A07C4441CF02206FDD7C1FA2E75DFC0B7262F7D90109A8DEB9CBD6E37B1899A99DA1F7FEF56D23300220F46F16CE1BE6BE703571D9A7FF87F387761A8836DDAE137A57089F0200324406183001407D81C56326B02912B0E51401F40CBB82898996BCF17A4AEA132F758693ED1D4B092F38E0FC38C706ED23B4522BC4B00F451F0B5F0B70BDF22073A479C3C0B2641818181824FF0C18";
        var payload = StringToByteArray(invokeResponsePayload);

        MatterTLV tlv = new MatterTLV(payload);

        Console.WriteLine(tlv.ToString());
    }

    [Test]
    public void GenerateDebugOutputForAddTrustedRootCertificateRequestPayload()
    {
        var invokeRequestPayload = "152800280136021537002500000026013E00000025020600183501310043013082013F3081E7A003020102020822174677C5D86B7F300A06082A8648CE3D040302300E310C300A060355040A0C03435352301E170D3235303433303131333634325A170D3335303433303131333634325A300E310C300A060355040A0C034353523059301306072A8648CE3D020106082A8648CE3D0301070342000499FB4BFD1696797E97650A8FAD7BC8E15E08CDF828FFB6B3AF8423710223FFE3D42125005553CB60A54C77FB33D2DBDE698D690AB710018A943BF5EF21A7F618A32F302D300C0603551D130101FF04023000301D0603551D0E0416041495072993174AE0749C79AEB1B3333B1B21FCE854300A06082A8648CE3D040302034700304402205F7DC3BAA39E56BADD7688B2AD5448D2AFDDB294D901151C7545F92CBDA57DBF022068659B2451729B81AF582D57B112594203AEC96271DC5C5E9C956F9EC40B222531021000C671960FA4D12B77C170F388A0F24AA02703707C8AAE40B2D1982504F1FF18181824FF0C18";

        var payload = StringToByteArray(invokeRequestPayload);

        MatterTLV tlv = new MatterTLV(payload);

        Console.WriteLine(tlv.ToString());
    }

    [Test]
    public void ReadCSRResponseInvokeResponse()
    {
        var invokeResponsePayload = "1528003601153500370024000024013E2402051835013000F2153001CA3081C73070020100300E310C300A060355040A0C034353523059301306072A8648CE3D020106082A8648CE3D030107034200041D9D44B582AED11DDEC2B7919A151BE30157E7A723FB98AF630B84452EA0B7922A2941CC130CC5240B578886D45993F33A84B4BDFE9801107C7F7029085651AAA000300A06082A8648CE3D0403020347003044022053888197B946AD0DA892199024699E3CEE56899B034D674938990181F4E76EC2022012E37AA45C8A4D90FEEEB1118754DCF0CDB31944A4396F2247DE67D0585FBC843002203554AF4837036DA332CC01A716D60DEE1D3A0C2928A8B3639D19A9D9688B761718300140D9610D1103799EF502E736491673B7FCA4BB4DC8BC98A1A2FF325BFB0D21F7EC2282967F4BDCA51923B78805EE344D8D4E2B297FEA0458655150F467E79956BE1818181824FF0C18";
        var payload = StringToByteArray(invokeResponsePayload);

        MatterTLV tlv = new MatterTLV(payload);

        Console.WriteLine(tlv.ToString());

        tlv.OpenStructure();
        tlv.GetBoolean(0);
        tlv.OpenArray(1);

        tlv.OpenStructure();
        tlv.OpenStructure(0);

        tlv.OpenList(0);
        tlv.GetUnsignedInt8(0);
        tlv.GetUnsignedInt8(1);
        tlv.GetUnsignedInt8(2);
        tlv.CloseContainer(); // Close list.

        tlv.OpenStructure(1);
        tlv.GetOctetString(0);
        tlv.GetOctetString(1);
        tlv.CloseContainer(); // Close structure.

        tlv.CloseContainer(); // Close structure.
        tlv.CloseContainer(); // Close structure.
        tlv.CloseContainer(); // Close structure.

        tlv.GetUnsignedInt8(255);
        tlv.CloseContainer(); // Close structure.
    }

    [Test]
    public void TestCertificateEncoding()
    {
        var encodedNocCertificate = new MatterTLV();
        encodedNocCertificate.AddStructure();

        encodedNocCertificate.AddOctetString(1, new BigInteger("111").ToByteArrayUnsigned()); // SerialNumber
        encodedNocCertificate.AddUInt8(2, 1); // signature-algorithm

        encodedNocCertificate.AddList(3); // Issuer
        encodedNocCertificate.AddUInt64(20, 0);
        encodedNocCertificate.EndContainer(); // Close List

        var notBefore = new DateTimeOffset().ToEpochTime();
        var notAfter = new DateTimeOffset().ToEpochTime();

        encodedNocCertificate.AddUInt32(4, (uint)notBefore); // NotBefore
        encodedNocCertificate.AddUInt32(5, (uint)notAfter); // NotAfter

        encodedNocCertificate.AddList(6); // Subject
        encodedNocCertificate.AddUTF8String(17, "2"); // NodeId
        encodedNocCertificate.AddUTF8String(21, "TestFabric"); // FabricId
        encodedNocCertificate.EndContainer(); // Close List

        encodedNocCertificate.AddUInt8(7, 1); // public-key-algorithm
        encodedNocCertificate.AddUInt8(8, 1); // elliptic-curve-id

        encodedNocCertificate.AddOctetString(9, new byte[65]); // PublicKey

        encodedNocCertificate.AddList(10); // Extensions

        encodedNocCertificate.AddStructure(1); // Basic Constraints
        encodedNocCertificate.AddBool(1, false); // is-ca
        encodedNocCertificate.EndContainer(); // Close Basic Constraints

        // 6.5.11.2.Key Usage Extension We want keyCertSign (0x20) and CRLSign (0x40)
        encodedNocCertificate.AddUInt8(2, 0x6);

        encodedNocCertificate.AddArray(3); // Extended Key Usage
        encodedNocCertificate.AddUInt8(0x02);
        encodedNocCertificate.AddUInt8(0x01);
        encodedNocCertificate.EndContainer();

        encodedNocCertificate.AddOctetString(4, new byte[0]); // subject-key-id
        encodedNocCertificate.AddOctetString(5, new byte[0]); // authority-key-id

        encodedNocCertificate.EndContainer(); // Close Extensions

        encodedNocCertificate.AddOctetString(11, new byte[64]);

        encodedNocCertificate.EndContainer(); // Close Structure

        Console.WriteLine(encodedNocCertificate);
    }

    [Test]
    public void TestUTF8()
    {
        var encodedNocCertificate = new MatterTLV();
        encodedNocCertificate.AddStructure();
        encodedNocCertificate.AddList(6); // Subject
        encodedNocCertificate.AddUTF8String(17, "2"); // NodeId
        encodedNocCertificate.AddUTF8String(21, "TestFabric"); // FabricId
        encodedNocCertificate.EndContainer(); // Close List
        encodedNocCertificate.EndContainer(); // Close Structure

        Console.WriteLine(encodedNocCertificate);
    }

    [Test]
    public void TestStream()
    {
        var encodedNocCertificate = new MatterTLV();
        encodedNocCertificate.AddStructure();
        encodedNocCertificate.AddList(6); // Subject
        encodedNocCertificate.AddUTF8String(17, "2"); // NodeId
        encodedNocCertificate.AddUTF8String(21, "TestFabric"); // FabricId
        encodedNocCertificate.EndContainer(); // Close List
        encodedNocCertificate.EndContainer(); // Close Structure

        encodedNocCertificate.OpenStructure();

        var hasTag1 = encodedNocCertificate.IsNextTag(1);
        Assert.IsFalse(hasTag1, "Expected no tag 1 at this point.");

        var hasTag6 = encodedNocCertificate.IsNextTag(6);
        Assert.IsTrue(hasTag6, "Expected tag 6 at this point.");

        encodedNocCertificate.OpenList(6); 

        while(!encodedNocCertificate.IsEndContainerNext())
        {
            encodedNocCertificate.GetUTF8String(17);
            encodedNocCertificate.GetUTF8String(21);
        }

        encodedNocCertificate.CloseContainer();
        encodedNocCertificate.CloseContainer();
    }

    public static byte[] StringToByteArray(string hex)
    {
        hex = hex.Replace("-", "");
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
}
