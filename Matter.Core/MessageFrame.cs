
namespace Matter.Core
{
    class MessageFrame
    {
        public MessageFrame(MessagePayload messagePayload)
        {
            MessagePayload = messagePayload;
        }

        public MessageFrame(byte[] payload)
        {
            Flags = (MessageFlags)payload[0];
            SessionID = BitConverter.ToUInt16(payload, 1);
            Security = (SecurityFlags)payload[3];
            Counter = BitConverter.ToUInt32(payload, 4);

            var headerLength = 8;

            if ((Flags & MessageFlags.SourceNodeID) != 0)
            {
                headerLength += 2;
                SourceNodeID = BitConverter.ToUInt64(payload,5);
            }

            var messagePayload = new byte[payload.Length - headerLength];

            Array.Copy(payload, headerLength, messagePayload, 0, payload.Length - headerLength);

            MessagePayload = new MessagePayload(messagePayload);
        }

        public MessageFlags Flags { get; set; }

        public ushort SessionID { get; set; }

        public SecurityFlags Security { get; set; }

        public uint Counter { get; set; }

        public ulong SourceNodeID { get; set; }

        public MessagePayload MessagePayload { get; set; }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write((byte)Flags);
            writer.Write(SessionID);
            writer.Write((byte)Security);
            writer.Write(Counter);

            if ((Flags & MessageFlags.SourceNodeID) != 0)
            {
                writer.Write(SourceNodeID);
            }

            MessagePayload.Serialize(writer);
        }
    }
}
