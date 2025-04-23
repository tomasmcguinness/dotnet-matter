using Matter.Core.Sessions;

namespace Matter.Core
{
    class MessageExchange
    {
        private ushort _exchangeId;
        private ISession _session;

        // For this, the role will always be Initiator.
        public MessageExchange(ushort exchangeId, ISession session)
        {
            _exchangeId = exchangeId;
            _session = session;
        }

        public async Task SendAsync(MessageFrame message)
        {
            message.MessageCounter = GlobalCounter.Counter;
            message.MessagePayload.ExchangeID = _exchangeId;

            await _session.SendAsync(message);
        }

        internal async Task<MessageFrame> ReceiveAsync()
        {
            // Wait for the btpSession to publish a MessageFrame
            //
            return await _session.ReadAsync();
        }
    }
}
