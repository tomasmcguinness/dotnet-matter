namespace Matter.Core.BTP
{
    class BTPFrame
    {
        public BTPControlFlags ControlFlags { get; set; }

        public byte[] Payload { get; set; }

        public ushort MessageLength { get; set; }

        public uint AcknowledgeNumber { get; set; }

        public uint Sequence { get; set; }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write((byte)ControlFlags);

            // If this is an acknowledge message, send the number we're acknowldgeing.
            //
            if ((ControlFlags & BTPControlFlags.Acknowledge) != 0)
            {
                writer.Write((byte)AcknowledgeNumber);
            }

            // If this isn't a handshake, include the sequence.
            //
            if ((ControlFlags & BTPControlFlags.Handshake) == 0)
            {
                writer.Write((byte)Sequence);
            }

            // If this is a Beginning message, we need to include the MessageLength.
            //
            if ((ControlFlags & BTPControlFlags.Beginning) != 0)
            {
                writer.Write(MessageLength);
            }

            writer.Write(Payload);
        }

        //Console.WriteLine("Beginning: {0}, Continuining: {1}, Ending: {2}", isBeginningSegment? "1" : "0", isContinuingSegment? "1" : "0", isBeginningSegment? "1" : "0");
    }
}
