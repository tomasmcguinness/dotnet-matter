using Matter.Core.BTP;

namespace Matter.Core
{
    class MessageExchange
    {
        private ushort _exchangeId;
        private BTPSession _btpSession;

        // For this, the role will always be Initiator.
        public MessageExchange(ushort exchangeId, BTPSession btpSession)
        {
            _exchangeId = exchangeId;
            _btpSession = btpSession;
        }

        public async Task SendAsync(MessageFrame message)
        {
            message.Counter = GlobalCounter.Counter;
            message.MessagePayload.ExchangeID = _exchangeId;

            await _btpSession.SendAsync(message);
        }

        internal async Task<MessageFrame> ReceiveAsync()
        {
            // Wait for the btpSession to publish a MessageFrame
            //
            return await _btpSession.MessageFrameChannel.Reader.ReadAsync();
        }
    }
}
