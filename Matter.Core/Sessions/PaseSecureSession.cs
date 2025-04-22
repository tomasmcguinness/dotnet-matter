using Matter.Core.BTP;
using System.Security.Cryptography;

namespace Matter.Core.Sessions
{
    internal class PaseSecureSession : ISession
    {
        private BTPSession _btpSession;

        private ushort _sessionId;

        public PaseSecureSession(BTPSession btpSession)
        {
            _btpSession = btpSession;

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

            await _btpSession.SendAsync(message);
        }

        public async Task<MessageFrame> ReadAsync()
        {
            var message = await _btpSession.MessageFrameChannel.Reader.ReadAsync();

            // TODO Decrypt the message.

            return message;
        }
    }
}