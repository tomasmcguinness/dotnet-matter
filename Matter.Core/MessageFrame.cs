using System.Text;

namespace Matter.Core
{
    public class MessageFrame
    {
        public MessageFrame()
        {
        }

        public MessageFrame(MessagePayload messagePayload)
        {
            MessagePayload = messagePayload;
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
