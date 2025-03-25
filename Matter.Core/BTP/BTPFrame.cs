using System.IO;

namespace Matter.Core.BTP
{
    class BTPFrame
    {
        public BTPControlFlags ControlFlags { get; set; }

        public byte[] Payload { get; set; }

        public ushort MessageLength { get; set; }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write((byte)ControlFlags);

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
