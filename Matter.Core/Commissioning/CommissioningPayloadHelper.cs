using Org.BouncyCastle.Utilities;
using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace Matter.Core.Commissioning
{
    public class CommissioningPayloadHelper
    {
        public CommissioningPayload ParseManualSetupCode(string manualSetupCode)
        {
            if (manualSetupCode.Length != 11 && manualSetupCode.Length != 21)
            {
                throw new ArgumentException("Manual setup code must be 11 or 21 characters long.");
            }

            byte byte1 = byte.Parse(manualSetupCode.Substring(0, 1));

            ushort discriminator = (ushort)(byte1 << 10);

            ushort byte2to6 = ushort.Parse(manualSetupCode.Substring(1, 5));

            discriminator |= (ushort)((byte2to6 & 0xC000) >> 6);

            return new CommissioningPayload()
            {
                Discriminator = discriminator
            };
        }

        public CommissioningPayload ParseQRCode(string qrCodePayload)
        {
            return new CommissioningPayload();
        }
    }
}
