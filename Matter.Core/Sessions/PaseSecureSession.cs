using System.Security.Cryptography;

namespace Matter.Core.Sessions
{
    internal class PaseSecureSession : ISession
    {
        private IConnection _connection;

        private ushort _sessionId;

        public PaseSecureSession(IConnection connection)
        {
            _connection = connection;

            using (var rng = RandomNumberGenerator.Create())
            {
                var randomBytes = new byte[2];

                rng.GetBytes(randomBytes);
                ushort trueRandom = BitConverter.ToUInt16(randomBytes, 0);

                _sessionId = trueRandom;

                Console.WriteLine($"Created PASE Secure Session: {_sessionId}");
            }
        }

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

        public async Task SendAsync(MessageFrame message)
        {
            // TODO Encrypt the message.

            //message.SessionID = _sessionId;

            await _connection.SendAsync(message);
        }

        public async Task<MessageFrame> ReadAsync()
        {
            var message = await _connection.ReadAsync();

            // TODO Decrypt the message.

            return message;
        }
    }
}