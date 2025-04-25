using System.Text;

namespace Matter.Core
{
    public class MessageFrame
    {
        public MessageFrame(MessagePayload messagePayload)
        {
            MessagePayload = messagePayload;
        }

        public MessageFrame(byte[] payload)
        {
            MessageFlags = (MessageFlags)payload[0];
            SessionID = BitConverter.ToUInt16(payload, 1);
            SecurityFlags = (SecurityFlags)payload[3];
            MessageCounter = BitConverter.ToUInt32(payload, 4);

            var headerLength = 8;

            if ((MessageFlags & MessageFlags.S) != 0)
            {
                // Account for the SourceNodeId (8 bytes)
                headerLength += 8;
                SourceNodeID = BitConverter.ToUInt64(payload, 5);
            }

            if ((MessageFlags & MessageFlags.DSIZ1) != 0)
            {
                headerLength += 8;
                DestinationNodeId = BitConverter.ToUInt64(payload, headerLength);
            }
            if ((MessageFlags & MessageFlags.DSIZ2) != 0)
            {
                headerLength += 2;
                SourceNodeID = BitConverter.ToUInt16(payload, headerLength);
            }

            var messagePayload = new byte[payload.Length - headerLength];

            Array.Copy(payload, headerLength, messagePayload, 0, payload.Length - headerLength);

            MessagePayload = new MessagePayload(messagePayload);
        }

        public MessageFlags MessageFlags { get; set; }

        public ushort SessionID { get; set; }

        public SecurityFlags SecurityFlags { get; set; }

        public uint MessageCounter { get; set; }

        public ulong SourceNodeID { get; set; }

        public ulong DestinationNodeId { get; set; }

        public MessagePayload MessagePayload { get; set; }

        public byte[]? EncryptedMessagePayload { get; set; }

        public override string ToString()
        {
            StringBuilder sb = new StringBuilder();
            return sb.ToString();
        }
    }
}
