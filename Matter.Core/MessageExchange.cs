namespace Matter.Core
{
    class MessageExchange
    {
        private ushort _exchangeId;
        private IConnection _connection;

        // For this, the role will always be Initiator.
        public MessageExchange(ushort exchangeId, IConnection connection)
        {
            _exchangeId = exchangeId;
            _connection = connection;
        }

        public async Task SendAsync(MessageFrame message)
        {
            message.MessageCounter = GlobalCounter.Counter;
            message.MessagePayload.ExchangeID = _exchangeId;

            await _connection.SendAsync(message);
        }

        internal async Task<MessageFrame> ReceiveAsync()
        {
            // Wait for the btpSession to publish a MessageFrame
            //
            return await _connection.ReadAsync();
        }
    }
}
