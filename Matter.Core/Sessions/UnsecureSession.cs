using Matter.Core.BTP;
using System.Security.Cryptography;

namespace Matter.Core.Sessions
{
    internal class UnsecureSession : ISession
    {
        private BTPSession _btpSession;

        public UnsecureSession(BTPSession btpSession)
        {
            _btpSession = btpSession;
        }

        public MessageExchange CreateExchange()
        {
            // We're going to Exchange messages in this session, so we need an MessageExchange 
            // to track it (4.10).
            //
            var randomBytes = new byte[2];

            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomBytes);
                ushort trueRandom = BitConverter.ToUInt16(randomBytes, 0);

                var exchangeId = trueRandom;

                Console.WriteLine($"Created Exchange ID: {exchangeId}");

                return new MessageExchange(exchangeId, this);
            }
        }

        public async Task SendAsync(MessageFrame message)
        {
            await _btpSession.SendAsync(message);
        }

        public async Task<MessageFrame> ReadAsync()
        {
            return await _btpSession.MessageFrameChannel.Reader.ReadAsync();
        }
    }
}