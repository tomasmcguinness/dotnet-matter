using System.Security.Cryptography;

namespace Matter.Core.Sessions
{
    public class UnsecureSession : ISession
    {
        private IConnection _connection;

        public UnsecureSession(IConnection connection)
        {
            _connection = connection;
            SessionId = 0;
        }

        public IConnection Connection => _connection;

        public IConnection CreateNewConnection()
        {
            return _connection.OpenConnection();
        }

        public ulong SourceNodeId { get; } = 0x00;

        public ulong DestinationNodeId { get; } = 0x00;

        public void Close()
        {
            _connection.Close();
        }

        public ushort SessionId { get; set; }

        public bool UseMRP => false;

        public MessageExchange CreateExchange()
        {
            // We're going to Exchange messages in this session, so we need an MessageExchange 
            // to track it (4.10). 
            //
            // TODO Ensure the ExchangeId is unique!
            //
            var randomBytes = new byte[2];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);

                ushort trueRandom = BitConverter.ToUInt16(randomBytes, 0);

                var exchangeId = trueRandom;

                Console.WriteLine($"Created Unsecure Exchange ID: {exchangeId}");

                return new MessageExchange(exchangeId, this);
            }
        }

        public async Task SendAsync(byte[] message)
        {
            await _connection.SendAsync(message);
        }

        public async Task<byte[]> ReadAsync()
        {
            return await _connection.ReadAsync();
        }

        public byte[] Encode(MessageFrame messageFrame)
        {
            var parts = new MessageFrameParts(messageFrame);
            return parts.Header.Concat(parts.MessagePayload).ToArray();
        }

        public MessageFrame Decode(byte[] payload)
        {
            var messageParts = new MessageFrameParts(payload);
            var messageFrame = messageParts.MessageFrameWithHeaders();
            messageFrame.MessagePayload = new MessagePayload(messageParts.MessagePayload);
            return messageFrame;
        }
    }
}