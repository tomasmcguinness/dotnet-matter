
namespace Matter.Core
{
    class MessageFrame
    {
        public MessageFrame(MessagePayload messagePayload)
        {
            MessagePayload = messagePayload;
        }

        public MessageFlags Flags { get; set; }

        public ushort SessionID { get; set; }

        public SecurityFlags Security { get; set; }

        public uint Counter { get; set; }

        public ulong SourceNodeID { get; set; }

        //public ulong DestinationID { get; set; }

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
