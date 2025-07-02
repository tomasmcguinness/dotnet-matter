using Matter.Core.Commissioning;

namespace Matter.Tests;

public class CommissioningPayloadHelperTests
{
    [Test]
    public void Test1()
    {
        var commissioningPayload = CommissioningPayloadHelper.ParseManualSetupCode("34970112332");
        Assert.That(commissioningPayload.Discriminator, Is.EqualTo(3840));
        Assert.That(commissioningPayload.Passcode, Is.EqualTo(20202021));
    }
}
