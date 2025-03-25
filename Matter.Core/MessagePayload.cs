namespace Matter.Core
{
    public class MessagePayload
    {
        public MessagePayload(MatterTLV payload)
        {
            Payload = payload;
        }

        public ExchangeFlags ExchangeFlags { get; set; }

        public byte ProtocolOpCode { get; set; }

        public ushort ProtocolId { get; set; }

        public ushort ExchangeID { get; set; }

        //public ushort VendorID { get; set; }

        //public uint AckCounter { get; set; }

        public MatterTLV Payload { get; set; }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write((byte)ExchangeFlags);
            writer.Write(ProtocolOpCode);
            writer.Write(ExchangeID);
            writer.Write(ProtocolId);

            // Write the bytes of the payload!
            Payload.Serialize(writer);
        }
    }
}