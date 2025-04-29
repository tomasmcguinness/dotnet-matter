using Matter.Core;

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

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
}
