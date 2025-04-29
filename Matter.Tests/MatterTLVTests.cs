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

    public static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
                         .Where(x => x % 2 == 0)
                         .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                         .ToArray();
    }
}
