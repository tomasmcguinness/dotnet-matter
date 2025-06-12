using Matter.Core.Fabrics;
using Matter.Core.InteractionModel;
using Matter.Core.Sessions;
using Matter.Core.TLV;
using Org.BouncyCastle.Math;
using System.Net;

namespace Matter.Core
{
    public class Node
    {
        public ISession _secureSession;

        public BigInteger NodeId { get; set; }

        public string NodeName => BitConverter.ToString(NodeId.ToByteArray().Reverse().ToArray()).Replace("-", "");

        public IPAddress? LastKnownIpAddress { get; set; }

        public ushort? LastKnownPort { get; set; }

        public Fabric Fabric { get; set; }

        public bool IsConnected { get; set; }

        public List<Endpoint> Endpoints { get; set; } = [];

        public async Task Connect(INodeRegister nodeRegister)
        {
            try
            {
                IPAddress? ipAddress = LastKnownIpAddress;
                ushort? port = LastKnownPort;

                //var addresses = nodeRegister.GetCommissionedNodeAddresses(Fabric.GetFullNodeName(this));

                //if (addresses.Count() == 0)
                //{
                //    IsConnected = false;
                //    return;
                //}

                var connection = new UdpConnection(ipAddress!, port!.Value);

                var unsecureSession = new UnsecureSession(connection);

                CASEClient client = new CASEClient(this, this.Fabric, unsecureSession);

                _secureSession = await client.EstablishSessionAsync();

                this.IsConnected = true;

                Console.WriteLine($"Established secure session to node {this.NodeId}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to establish connection to node {this.NodeId}: {ex.Message}");
                this.IsConnected = false;
            }
        }

        public async Task FetchDescriptionsAsync()
        {
            if (!IsConnected)
            {
                throw new Exception("Node is not connected. Please connect before interrogating.");
            }

            var exchange = _secureSession.CreateExchange();

            //var readCluster = new MatterTLV();
            //readCluster.AddStructure();

            //readCluster.AddArray(tagNumber: 0);

            //readCluster.AddList();

            //readCluster.AddBool(tagNumber: 0, false);
            ////readCluster.AddUInt64(tagNumber: 1, NodeId); // NodeId 0x00
            //readCluster.AddUInt16(tagNumber: 2, 0x00); // Endpoint 0x00
            //readCluster.AddUInt32(tagNumber: 3, 0x28); // ClusterId 0x28 - Basic Information
            //readCluster.AddUInt32(tagNumber: 4, 0x01); // Attribute 0x01 - Vendor Name
            ////readCluster.AddUInt16(tagNumber: 5, 0x00); // List Index 0x00
            ////readCluster.AddUInt32(tagNumber: 6, 0x00); // Wildcard flags
            //readCluster.EndContainer(); // Close the list

            //readCluster.EndContainer(); // Close the array

            //readCluster.AddArray(tagNumber: 1);
            //readCluster.EndContainer();

            //readCluster.AddArray(tagNumber: 2);
            //readCluster.EndContainer();

            //readCluster.AddBool(tagNumber: 3, false);

            //// Add the InteractionModelRevision number.
            ////
            //readCluster.AddUInt8(255, 12);

            //readCluster.EndContainer();

            //var readClusterMessagePayload = new MessagePayload(readCluster);

            //readClusterMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

            //// Table 14. Protocol IDs for the Matter Standard Vendor ID
            //readClusterMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
            //// From Table 18. Secure Channel Protocol Opcodes
            //readClusterMessagePayload.ProtocolOpCode = 0x2; // ReadRequest

            //var readClusterMessageFrame = new MessageFrame(readClusterMessagePayload);

            //readClusterMessageFrame.MessageFlags |= MessageFlags.S;
            //readClusterMessageFrame.SecurityFlags = 0x00;

            //await exchange.SendAsync(readClusterMessageFrame);

            //var readClusterResponseMessageFrame = await paseExchange.ReceiveAsync();

            var readCluster = new MatterTLV();
            readCluster.AddStructure();

            readCluster.AddArray(tagNumber: 0);

            readCluster.AddList();

            //readCluster.AddBool(tagNumber: 0, false);
            //readCluster.AddUInt16(tagNumber: 2, 0x00); // Endpoint 0x00
            readCluster.AddUInt32(tagNumber: 3, 0x1D); // ClusterId 0x1D - Description
            readCluster.AddUInt32(tagNumber: 4, 0x00); // Attribute 0x00 - DeviceTypeList
            //readCluster.AddUInt16(tagNumber: 5, 0x00); // List Index 0x00
            //readCluster.AddUInt32(tagNumber: 6, 0x00); // Wildcard flags
            readCluster.EndContainer(); // Close the list

            //readCluster.AddList();

            //readCluster.AddBool(tagNumber: 0, false);
            //readCluster.AddUInt16(tagNumber: 2, 0x00); // Endpoint 0x00
            //readCluster.AddUInt32(tagNumber: 3, 0x1D); // ClusterId 0x1D - Description
            //readCluster.AddUInt32(tagNumber: 4, 0x03); // Attribute 0x03 - PartsTypeList
            ////readCluster.AddUInt16(tagNumber: 5, 0x00); // List Index 0x00
            ////readCluster.AddUInt32(tagNumber: 6, 0x00); // Wildcard flags
            //readCluster.EndContainer(); // Close the list

            readCluster.EndContainer(); // Close the array

            readCluster.AddArray(tagNumber: 1);
            readCluster.EndContainer();

            readCluster.AddArray(tagNumber: 2);
            readCluster.EndContainer();

            readCluster.AddBool(tagNumber: 3, false);

            // Add the InteractionModelRevision number.
            //
            readCluster.AddUInt8(255, 12);

            readCluster.EndContainer();

            var readClusterMessagePayload = new MessagePayload(readCluster);

            readClusterMessagePayload.ExchangeFlags |= ExchangeFlags.Initiator;

            // Table 14. Protocol IDs for the Matter Standard Vendor ID
            readClusterMessagePayload.ProtocolId = 0x01; // IM Protocol Messages
            // From Table 18. Secure Channel Protocol Opcodes
            readClusterMessagePayload.ProtocolOpCode = 0x2; // ReadRequest

            var readClusterMessageFrame = new MessageFrame(readClusterMessagePayload);

            readClusterMessageFrame.MessageFlags |= MessageFlags.S;
            readClusterMessageFrame.SecurityFlags = 0x00;

            await exchange.SendAsync(readClusterMessageFrame);

            var readClusterResponseMessageFrame = await exchange.WaitForNextMessageAsync();

            await exchange.AcknowledgeMessageAsync(readClusterMessageFrame.MessageCounter);

            var resultPayload = readClusterResponseMessageFrame.MessagePayload;

            // Parse this into a set of endpoints.
            //
            var tlv = resultPayload.ApplicationPayload;

            Console.WriteLine(tlv);

            var reportData = new ReportDataAction(tlv);

            exchange.Close();
        }
    }
}