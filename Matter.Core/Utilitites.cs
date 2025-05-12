using Matter.Core.TLV;
using Org.BouncyCastle.X509;

namespace Matter.Core
{
    public static class Extensions
    {
        public static byte[] ToByteArray(this string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static uint ToEpochTime(this DateTimeOffset dt)
        {
            var epochStart = 946684800; // 2000-01-01T00:00:00Z
            return (uint)(dt.ToUnixTimeSeconds() - epochStart);
        }

        public static string DebugInfo(this MessageFrame message)
        {
            var (protocolName, protocolOpName) = GetFriendlyNames(message.MessagePayload);
            return string.Format("{0} | {1} | {2}", message.MessageCounter, protocolName, protocolOpName);
        }

        public static string DebugInfo(this MessagePayload message)
        {
            var (protocolName, protocolOpName) = GetFriendlyNames(message);
            return string.Format("{0} | {1} | {2} | {3}", message.ExchangeFlags, message.ExchangeID, protocolName, protocolOpName);
        }

        private static (string protocolId, string protocolOpCode) GetFriendlyNames(MessagePayload messagePayload)
        {
            var protocolName = messagePayload.ProtocolId.ToProtocolName();
            var protocolOpName = messagePayload.ProtocolOpCode.ToProtocolOpName(messagePayload.ProtocolId);

            return (protocolName, protocolOpName);
        }

        public static string ToProtocolName(this ushort protocolId)
        {
            switch (protocolId)
            {
                case 0x00:
                    return "Secure";
                case 0x01:
                    return "InteractionModel";
                default:
                    return protocolId.ToString("X4");
            }
        }

        public static string ToProtocolOpName(this byte opCode, ushort protocolId)
        {
            if (protocolId == 0x00)
            {
                switch (opCode)
                {
                    case 0x10:
                        return "MRP Standalone Acknowledgement";
                    case 0x20:
                        return "PBKDFParamRequest";
                    case 0x21:
                        return "PBKDFParamResponse";
                    case 0x22:
                        return "PASE Pake1";
                    case 0x23:
                        return "PASE Pake2";
                    case 0x24:
                        return "PASE Pake3";
                    case 0x30:
                        return "CASE Sigma1";
                    case 0x31:
                        return "CASE Sigma2";
                    case 0x32:
                        return "CASE Sigma3";
                    case 0x40:
                        return "StatusReport";
                }
            }
            else if (protocolId == 0x01)
            {
                switch (opCode)
                {
                    case 0x02:
                        return "Read Request";
                    case 0x05:
                        return "Report Data";
                    case 0x08:
                        return "Invoke Request";
                    case 0x09:
                        return "Invoke Response";
                }
            }

            return "";
        }

        public static MatterTLV ToMatterCertificate(this X509Certificate certificate)
        {
            var certificateBytes = certificate.GetEncoded();
            var tlv = new MatterTLV();
            return tlv;
        }
    }
}
