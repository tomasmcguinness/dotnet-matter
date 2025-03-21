namespace Matter.Core.BTP
{
    class BTPPacket
    {
        public byte ControlFlags { get; set; }

        public byte ManagementOpCode { get; set; }

        public byte AckNumber { get; set; }

        public byte SequenceNumber { get; set; }

        public ushort Length { get; set; }

        public byte[] Payload { get; set; }

    }
}
