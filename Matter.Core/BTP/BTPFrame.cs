using System.Security.AccessControl;

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

            // If it's not a handshake result, log the contents.
            //
            // Print some of the common stuff.
            //
            Console.WriteLine("Control Flags {0}", Convert.ToString(readData[0], 2).PadLeft(8, '0'));

            // Check the ControlFlags.
            //
            var isHandshake = ((byte)ControlFlags & 0x20) != 0;
            var isManagement = ((byte)ControlFlags & 0x10) != 0;
            var isAcknowledgement = ((byte)ControlFlags & 0x8) != 0;
            var isEndingSegment = ((byte)ControlFlags & 0x4) != 0;
            var isContinuingSegment = ((byte)ControlFlags & 0x2) != 0;
            var isBeginningSegment = ((byte)ControlFlags & 0x1) != 0;

            int byteIndex = 1;

            if (isManagement)
            {
                Console.WriteLine("Management OpCode {0}", Convert.ToString(readData[byteIndex++], 2).PadLeft(8, '0'));
            }

            // The device is acknowledging a packet we send.
            //
            if (isAcknowledgement)
            {
                Console.WriteLine("Acknowledged Number {0}", readData[byteIndex++]);
            }

            Console.WriteLine("Beginning: {0}, Continuining: {1}, Ending: {2}", isBeginningSegment ? "1" : "0", isContinuingSegment ? "1" : "0", isBeginningSegment ? "1" : "0");
        }

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
