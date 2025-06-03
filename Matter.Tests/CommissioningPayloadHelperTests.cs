using Matter.Core.Commissioning;

namespace Matter.Tests;

public class CommissioningPayloadHelperTests
{
    [Test]
    public void Test1()
    {
        CommissioningPayloadHelper helper = new CommissioningPayloadHelper();
        var commissioningPayload = helper.ParseManualSetupCode("34970112332");
        Assert.That(commissioningPayload.Discriminator, Is.EqualTo(3840));
    }
}
