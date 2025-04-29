using System.Security.Cryptography;

namespace Matter.Core.Sessions
{
    internal class PaseSecureSession : ISession
    {
        private readonly IConnection _connection;
        private readonly byte[] _encryptionKey;
        private readonly byte[] _decryptionKey;

        public PaseSecureSession(IConnection connection, ushort sessionId, byte[] encryptionKey, byte[] decryptionKey)
        {
            _connection = connection;
            _encryptionKey = encryptionKey;
            _decryptionKey = decryptionKey;

            using (var rng = RandomNumberGenerator.Create())
            {
                //var randomBytes = new byte[2];

                //rng.GetBytes(randomBytes);
                //ushort trueRandom = BitConverter.ToUInt16(randomBytes, 0);

                SessionId = sessionId;

                Console.WriteLine($"Created PASE Secure Session: {SessionId}");
            }

            _decryptionKey = decryptionKey;
        }

        public ushort SessionId { get; }

        public MessageExchange CreateExchange()
        {
            // We're going to Exchange messages in this session, so we need an MessageExchange 
            // to track it (4.10).
            //
            using (var rng = RandomNumberGenerator.Create())
            {
                var randomBytes = new byte[2];

                rng.GetBytes(randomBytes);
                ushort trueRandom = BitConverter.ToUInt16(randomBytes, 0);

                var exchangeId = trueRandom;

                Console.WriteLine($"Created Exchange ID: {exchangeId}");
                return new MessageExchange(exchangeId, this);
            }
        }

        public async Task SendAsync(byte[] message)
        {
            // TODO Encrypt the message.

            //message.SessionID = _sessionId;

            await _connection.SendAsync(message);
        }

        public async Task<byte[]> ReadAsync()
        {
            var message = await _connection.ReadAsync();

            // TODO Decrypt the message.

            return message;
        }

        public byte[] Encode(MessageFrame messageFrame)
        {
            var parts = new MessageFrameParts(messageFrame);

            var memoryStream = new MemoryStream();
            var nonceWriter = new BinaryWriter(memoryStream);

            nonceWriter.Write((byte)messageFrame.SecurityFlags);
            nonceWriter.Write(BitConverter.GetBytes(messageFrame.MessageCounter));
            nonceWriter.Write(BitConverter.GetBytes(messageFrame.SourceNodeID));

            var nonce = memoryStream.ToArray();

            Console.WriteLine("Nonce: {0}", BitConverter.ToString(nonce));

            memoryStream = new MemoryStream();
            var additionalDataWriter = new BinaryWriter(memoryStream);

            additionalDataWriter.Write((byte)messageFrame.MessageFlags);
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.SessionID));
            additionalDataWriter.Write((byte)messageFrame.SecurityFlags);
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.MessageCounter));
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.SourceNodeID));

            var additionalData = memoryStream.ToArray();

            Console.WriteLine("Additional Data: {0}", BitConverter.ToString(additionalData));

            byte[] encryptedPayload = new byte[parts.Payload.Length];
            byte[] tag = new byte[16];

            var encryptor = new AesCcm(_encryptionKey);
            encryptor.Encrypt(nonce, parts.Payload, encryptedPayload, tag, additionalData);

            var totalPayload = encryptedPayload.Concat(tag);

            return parts.Header.Concat(totalPayload).ToArray();
        }

        public MessageFrame Decode(byte[] payload)
        {
            // Run this through the decoder. We need to start reading the bytes until we 
            // get to the payload. We then need to decrypt the payload.
            //
            var parts = new MessageFrameParts(payload);

            Console.WriteLine("Incoming Header: {0}", BitConverter.ToString(parts.Header));
            Console.WriteLine("Incoming Payload: {0}", BitConverter.ToString(parts.Payload));

            var messageFrame = parts.MessageFrameWithHeaders();

            var memoryStream = new MemoryStream();
            var nonceWriter = new BinaryWriter(memoryStream);

            nonceWriter.Write((byte)messageFrame.SecurityFlags);
            nonceWriter.Write(BitConverter.GetBytes(messageFrame.MessageCounter));
            nonceWriter.Write(BitConverter.GetBytes(messageFrame.SourceNodeID));

            var nonce = memoryStream.ToArray();

            Console.WriteLine("Nonce: {0}", BitConverter.ToString(nonce));

            memoryStream = new MemoryStream();
            var additionalDataWriter = new BinaryWriter(memoryStream);

            additionalDataWriter.Write((byte)messageFrame.MessageFlags);
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.SessionID));
            additionalDataWriter.Write((byte)messageFrame.SecurityFlags);
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.MessageCounter));
            additionalDataWriter.Write(BitConverter.GetBytes(messageFrame.SourceNodeID));

            var additionalData = memoryStream.ToArray();

            Console.WriteLine("Additional Data: {0}", BitConverter.ToString(additionalData));

            byte[] decryptedPayload = new byte[parts.Payload.Length - 16];

            var tag = parts.Payload.AsSpan().Slice(parts.Payload.Length - 16, 16);
            var encryptedPayload = parts.Payload.AsSpan().Slice(0, parts.Payload.Length - 16);

            var encryptor = new AesCcm(_decryptionKey);
            encryptor.Decrypt(nonce, encryptedPayload, tag, decryptedPayload, additionalData);

            messageFrame.MessagePayload = new MessagePayload(decryptedPayload);

            return messageFrame;
        }
    }
}