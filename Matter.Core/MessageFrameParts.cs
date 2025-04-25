namespace Matter.Core
{
    internal class MessageFrameParts
    {
        public MessageFrameParts(MessageFrame messageFrame)
        {
            var headerWriter = new MatterMessageWriter();

            headerWriter.Write((byte)messageFrame.MessageFlags);
            headerWriter.Write(messageFrame.SessionID);
            headerWriter.Write((byte)messageFrame.SecurityFlags);
            headerWriter.Write(messageFrame.MessageCounter);

            if ((messageFrame.MessageFlags & MessageFlags.S) != 0)
            {
                headerWriter.Write(messageFrame.SourceNodeID);
            }

            Header = headerWriter.GetBytes();

            var payloadWriter = new MatterMessageWriter();
            messageFrame.MessagePayload.Serialize(payloadWriter);

            Payload = payloadWriter.GetBytes();
        }

        public byte[] Header { get; set; }

        public byte[] Payload { get; set; }
    }
}
