using Matter.Core.BTP;
using Matter.Core.Discovery;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Windows.Devices.Bluetooth;
using Windows.Devices.Bluetooth.Advertisement;
using Windows.Storage.Streams;

namespace Matter.Core.Commissioning
{
    public class NetworkCommissioningThread
    {
        private readonly int _discriminator;
        private readonly ManualResetEvent _resetEvent;
        private readonly List<ulong> _receivedAdvertisments = new();

        public NetworkCommissioningThread(int number, ManualResetEvent resetEvent)
        {
            _discriminator = number;
            _resetEvent = resetEvent;
        }

        public void PerformDiscovery()
        {
            CommissionOnNetworkDevice().Wait();
        }

        private async Task CommissionOnNetworkDevice()
        {
            //var discoverer = new DnsDiscoverer();
            //await discoverer.DiscoverCommissionableNodes();

            try
            {
                IConnection udpConnection = new UdpConnection();

                Console.WriteLine("UDP Connection has been established. Starting PASE Exchange....");

                // We're going to Exchange messages, so we need an MessageExchange 
                // to track it (4.10).
                //
                var exchangeId = (ushort)22; // TODO Make random!
                var exchange = new MessageExchange(exchangeId, udpConnection);

                // Perform the PASE exchange.
                //
                var PBKDFParamRequest = new MatterTLV();
                PBKDFParamRequest.AddStructure();

                // We need a control octet, the tag, the length and the value.
                //
                PBKDFParamRequest.AddOctetString4(1, RandomNumberGenerator.GetBytes(32));
                PBKDFParamRequest.AddUShort(2, (ushort)Random.Shared.Next(1, ushort.MaxValue));
                PBKDFParamRequest.AddUShort(3, 0);
                PBKDFParamRequest.AddBool(4, false);
                PBKDFParamRequest.EndContainer();

                // Construct a payload to carry this TLV message.
                //
                var messagePayload = new MessagePayload(PBKDFParamRequest);

                messagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

                // Table 14. Protocol IDs for the Matter Standard Vendor ID
                messagePayload.ProtocolId = 0x00;
                // From Table 18. Secure Channel Protocol Opcodes
                messagePayload.ProtocolOpCode = 0x20;

                var messageFrame = new MessageFrame(messagePayload);

                // The Message Header
                // The Session ID field SHALL be set to 0.
                // The Session Type bits of the Security Flags SHALL be set to 0.
                // In the PASE messages from the initiator, S Flag SHALL be set to 1 and DSIZ SHALL be set to 0.
                //
                // Message Flags (1byte) 0000100 0x04
                // SessionId (2bytes) 0x00
                // SecurityFlags (1byte) 0x00
                //
                messageFrame.Flags |= MessageFlags.SourceNodeID;
                messageFrame.SessionID = 0x00;
                messageFrame.Security = 0x00;

                // Generate a random SourceNodeId
                //
                Random random = new Random();
                long myRandomNumber = random.NextInt64(1, long.MaxValue);
                messageFrame.SourceNodeID = (ulong)myRandomNumber;

                await exchange.SendAsync(messageFrame);
                var responseMessageFrame = await exchange.ReceiveAsync();

                Console.WriteLine("Message received");
                Console.WriteLine("OpCode: {0:X2}", responseMessageFrame.MessagePayload.ProtocolId);
                Console.WriteLine("ProtocolId: {0:X2}", responseMessageFrame.MessagePayload.ProtocolOpCode);

                _resetEvent.Set();
            }
            catch
            {

            }
        }
    }

    public class NetworkCommissioner
    {
        public void CommissionDevice(int discriminator)
        {
            ManualResetEvent resetEvent = new ManualResetEvent(false);

            // Run the commissioning in a thread.
            //
            var commissioningThread = new NetworkCommissioningThread(discriminator, resetEvent);

            new Thread(new ThreadStart(commissioningThread.PerformDiscovery)).Start();

            // Give the thread some time to complete commissioning.
            //
            resetEvent.WaitOne(60000);
        }
    }
}