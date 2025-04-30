using Matter.Core.TLV;

namespace Matter.Tests;

public class MatterTLVTests
{
    [SetUp]
    public void Setup()
    {
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

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
}
