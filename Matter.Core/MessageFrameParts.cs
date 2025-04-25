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

        public MessageFrameParts(byte[] messageFrameBytes)
        {
            var messageFlags = (MessageFlags)messageFrameBytes[0];
            var SessionID = BitConverter.ToUInt16(messageFrameBytes, 1);
            var SecurityFlags = (SecurityFlags)messageFrameBytes[3];
            var MessageCounter = BitConverter.ToUInt32(messageFrameBytes, 4);

            var headerLength = 8; // SessionId (1), SecurityFlags(3), MessageCounter (4)

            if ((messageFlags & MessageFlags.S) != 0)
            {
                // Account for the SourceNodeId (8 bytes)
                headerLength += 8;
            }

            if ((messageFlags & MessageFlags.DSIZ1) != 0)
            {
                // Account for the SourceNodeId (8 bytes)
                headerLength += 8;
            }

            if ((messageFlags & MessageFlags.DSIZ2) != 0)
            {
                // Account for the SourceNodeId (8 bytes)
                headerLength += 2;
            }

            var messageHeader = new byte[headerLength];
            var messagePayload = new byte[messageFrameBytes.Length - headerLength];

            Array.Copy(messageFrameBytes, 0, messageHeader, 0, headerLength);
            Array.Copy(messageFrameBytes, headerLength, messagePayload, 0, messageFrameBytes.Length - headerLength);

            Header = messageHeader;
            Payload = messagePayload;
        }

        public byte[] Header { get; set; }

        public byte[] Payload { get; set; }

        internal MessageFrame MessageFrameWithHeaders()
        {
            var messageFrame = new MessageFrame();

            messageFrame.MessageFlags = (MessageFlags)Header[0];
            messageFrame.SessionID = BitConverter.ToUInt16(Header, 1);
            messageFrame.SecurityFlags = (SecurityFlags)Header[3];
            messageFrame.MessageCounter = BitConverter.ToUInt32(Header, 4);

            var headerLength = 8;

            if ((messageFrame.MessageFlags & MessageFlags.S) != 0)
            {
                // Account for the SourceNodeId (8 bytes)
                messageFrame.SourceNodeID = BitConverter.ToUInt64(Header, 5);
                headerLength += 8;
            }

            if ((messageFrame.MessageFlags & MessageFlags.DSIZ1) != 0)
            {
                messageFrame.DestinationNodeId = BitConverter.ToUInt64(Header, headerLength);
                headerLength += 8;

            }

            if ((messageFrame.MessageFlags & MessageFlags.DSIZ2) != 0)
            {
                messageFrame.SourceNodeID = BitConverter.ToUInt16(Header, headerLength);
                headerLength += 2;
            }

            return messageFrame;
        }
    }
}
