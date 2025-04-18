using Matter.Core.Sessions;

namespace Matter.Core
{
    class MessageExchange
    {
        private readonly ushort _exchangeId;
        private readonly ISession _session;

        // For this, the role will always be Initiator.
        //
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
            return await _session.ReadAsync();
        }
    }
}
