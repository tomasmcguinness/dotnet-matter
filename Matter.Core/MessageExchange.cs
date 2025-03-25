﻿using Matter.Core.BTP;

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

            _btpSession.SendAsync(message);
        }
    }
}
