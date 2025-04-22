namespace Matter.Core.BTP
{
    class BTPFrame
    {
        public BTPFrame()
        {

        }

        public BTPFrame(byte[] readData)
        {
            ControlFlags = (BTPControlFlags)readData[0];

            Console.WriteLine("Control Flags Byte: {0}", Convert.ToString(readData[0], 2).PadLeft(8, '0'));

            // Check the ControlFlags.
            //
            var isHandshake = ((byte)ControlFlags & 0x20) != 0;
            var isManagement = ((byte)ControlFlags & 0x10) != 0;
            var isAcknowledgement = ((byte)ControlFlags & 0x8) != 0;
            var isEndingSegment = ((byte)ControlFlags & 0x4) != 0;
            var isContinuingSegment = ((byte)ControlFlags & 0x2) != 0;
            var isBeginningSegment = ((byte)ControlFlags & 0x1) != 0;

            if (isHandshake)
            {
                Version = readData[2];
                ATTSize = BitConverter.ToUInt16(readData, 3);
                WindowSize = readData[5];

                // Nothing more to do here.
                return;
            }

            var headerSize = 1; // ControlFlags is mandatory.

            if (isManagement)
            {
                // TODO Grab the Management OpCode.
                headerSize += 1;
            }

            if (isBeginningSegment)
            {
                MessageLength = BitConverter.ToUInt16(readData, headerSize);
                headerSize += 2;
            }

            if (isAcknowledgement)
            {
                AcknowledgeNumber = readData[headerSize];
                headerSize += 1;
            }

            if (isBeginningSegment || isContinuingSegment || isEndingSegment)
            {
                Sequence = readData[headerSize];
                
                headerSize++;

                Payload = new byte[readData.Length - headerSize];
                
                Array.Copy(readData, headerSize, Payload, 0, readData.Length - headerSize);
            }
        }

        public BTPControlFlags ControlFlags { get; set; }

        public byte[] Payload { get; set; }

        public ushort MessageLength { get; set; }

        public byte AcknowledgeNumber { get; set; }

        public byte Sequence { get; set; }

        public ushort Version { get; }

        public ushort ATTSize { get; }

        public ushort WindowSize { get; }

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
    }
}
