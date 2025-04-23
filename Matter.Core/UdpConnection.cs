using System.Net;
using System.Net.Sockets;

namespace Matter.Core
{
    internal class UdpConnection : IConnection
    {
        private UdpClient _udpClient;

        private uint _receivedMessageCounter = 255;
        private uint _acknowledgedMessageCounter = 255;

        private readonly Timer _acknowledgementTimer;

        public UdpConnection()
        {
            _udpClient = new UdpClient(11000);
            IPAddress address = IPAddress.Parse("172.16.47.60");
            _udpClient.Connect(address, 5540);

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

        public async Task<MessageFrame> ReadAsync()
        {
            var receiveResult = await _udpClient.ReceiveAsync();
            MessageFrame messageFrame = new MessageFrame(receiveResult.Buffer);

            if ((messageFrame.MessagePayload.ExchangeFlags & ExchangeFlags.Reliability) != 0)
            {
                _receivedMessageCounter = messageFrame.MessageCounter;
            }

            Console.WriteLine("Received MessageCounter {0}", messageFrame.MessageCounter);

            return messageFrame;
        }

        public async Task SendAsync(MessageFrame message)
        {
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

            var writer = new MatterMessageWriter();

            message.Serialize(writer);

            var bytes = writer.GetBytes();

            await _udpClient.SendAsync(bytes);
        }
    }
}
