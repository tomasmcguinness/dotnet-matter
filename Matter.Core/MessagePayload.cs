namespace Matter.Core
{
    public class MessagePayload
    {
        public MessagePayload(MatterTLV payload)
        {
            Payload = payload;
        }

        public MessagePayload(byte[] messagePayload)
        {
            ExchangeFlags = (ExchangeFlags)messagePayload[0];
            ProtocolOpCode = messagePayload[1];
            ExchangeID = BitConverter.ToUInt16(messagePayload, 2);
            // TODO Protovol VendorId
            ProtocolId = BitConverter.ToUInt16(messagePayload, 4);
            // TODO Acknowledged Message Counter
            // TODO Secured Extensions
            Payload = new MatterTLV(messagePayload.AsSpan<byte>().Slice(6).ToArray());
        }

        public ExchangeFlags ExchangeFlags { get; set; }

        public byte ProtocolOpCode { get; set; }

        public ushort ProtocolId { get; set; }

        public ushort ExchangeID { get; set; }

        public MatterTLV Payload { get; set; }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write((byte)ExchangeFlags);
            writer.Write(ProtocolOpCode);
            writer.Write(ExchangeID);
            writer.Write(ProtocolId);

            // Write the bytes of the payload!
            //
            Payload.Serialize(writer);
        }        
    }
}