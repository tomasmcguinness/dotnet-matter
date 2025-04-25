using Matter.Core.Sessions;

namespace Matter.Core
{
    class MessageExchange
    {
        private ushort _exchangeId;
        private ISession _session;

        private uint _receivedMessageCounter = 255;
        private uint _acknowledgedMessageCounter = 255;

        private readonly Timer _acknowledgementTimer;


        // For this, the role will always be Initiator.
        //
        public MessageExchange(ushort exchangeId, ISession session)
        {
            _exchangeId = exchangeId;
            _session = session;

            _acknowledgementTimer = new Timer(SendStandaloneAcknowledgement, null, 2000, 5000);
        }

        private async void SendStandaloneAcknowledgement(object? state)
        {
            if (_acknowledgedMessageCounter != _receivedMessageCounter)
            {
                Console.WriteLine("Standalone Acknowledgement for MessageCounter {0}", _receivedMessageCounter);

                _acknowledgedMessageCounter = _receivedMessageCounter;

                MessagePayload payload = new MessagePayload();
                payload.ExchangeFlags |= ExchangeFlags.Acknowledgement;
                payload.AcknowledgedMessageCounter = _acknowledgedMessageCounter;
                payload.ProtocolOpCode = 0x00;
                payload.ProtocolId = 0x10; // MRP Standalone Acknowledgement

                MessageFrame messageFrame = new MessageFrame(payload);
                messageFrame.MessageFlags |= MessageFlags.S;
                messageFrame.SecurityFlags = 0x00;

                await SendAsync(messageFrame);
            }
        }

        public async Task SendAsync(MessageFrame message)
        {
            message.MessagePayload.ExchangeID = _exchangeId;

            // If this message doesn't include an acknowledgement already, check 
            // if we need to add one.
            //
            if ((message.MessagePayload.ExchangeFlags & ExchangeFlags.Acknowledgement) == 0)
            {
                if (_acknowledgedMessageCounter != _receivedMessageCounter)
                {
                    Console.WriteLine("Including Acknowledgement for MessageCounter {0}", _receivedMessageCounter);

                    _acknowledgedMessageCounter = _receivedMessageCounter;

                    message.MessagePayload.ExchangeFlags |= ExchangeFlags.Acknowledgement;
                    message.MessagePayload.AcknowledgedMessageCounter = _acknowledgedMessageCounter;
                }
            }

            var bytes = _session.Encode(message);

            await _session.SendAsync(bytes);
        }

        internal async Task<MessageFrame> ReceiveAsync()
        {
            var bytes = await _session.ReadAsync();

            var messageFrame = _session.Decode(bytes);

            if ((messageFrame.MessagePayload.ExchangeFlags & ExchangeFlags.Reliability) != 0)
            {
                _receivedMessageCounter = messageFrame.MessageCounter;
            }

            Console.WriteLine("Received MessageCounter {0}", messageFrame.MessageCounter);

            return messageFrame;
        }
    }
}
