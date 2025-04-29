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

            //_acknowledgementTimer = new Timer(SendStandaloneAcknowledgement, null, 5000, 5000);
        }

        private async void SendStandaloneAcknowledgement(object? state)
        {
            if (_acknowledgedMessageCounter != _receivedMessageCounter)
            {
                _acknowledgedMessageCounter = _receivedMessageCounter;

                await AcknowledgeMessageAsync(_acknowledgedMessageCounter);
            }
        }

        public async Task SendAsync(MessageFrame message)
        {
            // Set the common data on the MessageFrame.
            //
            message.SessionID = _session.SessionId;
            message.MessagePayload.ExchangeID = _exchangeId;
            message.MessageCounter = GlobalCounter.Counter;

            // Do we have any unacknowledged messages?
            // If yes, add the acknowledgement to this outgoing message.
            //
            if (_acknowledgedMessageCounter != _receivedMessageCounter)
            {
                Console.WriteLine("Including Acknowledgement for MessageCounter {0}", _receivedMessageCounter);

                _acknowledgedMessageCounter = _receivedMessageCounter;

                message.MessagePayload.ExchangeFlags |= ExchangeFlags.Acknowledgement;
                message.MessagePayload.AcknowledgedMessageCounter = _acknowledgedMessageCounter;
            }

            // TODO Turn the ProtocolId and OpCode into nice names.
            //
            Console.WriteLine(">>> Sending Message {0} | {1:X2} | {2:X2}", message.MessageCounter, message.MessagePayload.ProtocolId, message.MessagePayload.ProtocolOpCode);

            var bytes = _session.Encode(message);

            await _session.SendAsync(bytes);
        }

        public async Task<MessageFrame> ReceiveAsync()
        {
            var bytes = await _session.ReadAsync();

            var messageFrame = _session.Decode(bytes);

            if ((messageFrame.MessagePayload.ExchangeFlags & ExchangeFlags.Reliability) != 0)
            {
                _receivedMessageCounter = messageFrame.MessageCounter;
            }

            Console.WriteLine("Received Message {0}", messageFrame.MessageCounter);

            return messageFrame;
        }

        public async Task AcknowledgeMessageAsync(uint messageCounter)
        {
            MessagePayload payload = new MessagePayload();
            payload.ExchangeFlags |= ExchangeFlags.Acknowledgement;
            payload.ExchangeFlags |= ExchangeFlags.Initiator;
            payload.AcknowledgedMessageCounter = messageCounter;
            payload.ProtocolId = 0x00; // Secure Channel
            payload.ProtocolOpCode = 0x10; // MRP Standalone Acknowledgement

            MessageFrame messageFrame = new MessageFrame(payload);
            messageFrame.MessageFlags |= MessageFlags.S;
            messageFrame.SecurityFlags = 0x00;
            messageFrame.SessionID = _session.SessionId;
            messageFrame.MessageCounter = GlobalCounter.Counter;

            await SendAsync(messageFrame);

            Console.WriteLine("Sent Acknowledgement for MessageCounter {0}", _receivedMessageCounter);
        }
    }
}
