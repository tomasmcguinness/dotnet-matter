﻿using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using System.Net;
using System.Text.Json;

namespace Matter.Core.Fabrics
{
    public class FabricDiskStorage : IFabricStorageProvider
    {
        private readonly string _rootDirectory;

        public FabricDiskStorage(string rootDirectory)
        {
            _rootDirectory = rootDirectory;

            if (!Directory.Exists(_rootDirectory))
            {
                Directory.CreateDirectory(_rootDirectory);
            }
        }

        private class FabricDetails
        {
            public byte[] FabricId { get; set; }

            public byte[] RootCertificateId { get; set; }

            public byte[] RootNodeId { get; set; }

            public ushort AdminVendorId { get; set; }

            public byte[] IPK { get; set; }

            public byte[] OperationalIPK { get; set; }

            public byte[] RootKeyIdentifier { get; set; }

            public string CompressedFabricId { get; set; }
        }

        private class NodeDetails
        {
            public byte[] NodeId { get; set; }

            public string LastKnownIPAddress { get; set; }

            public ushort LastKnownPort { get; set; }
        }

        public bool DoesFabricExist(string fabricName)
        {
            return Directory.Exists(GetFullPath(fabricName));
        }

        public async Task<Fabric> LoadFabricAsync(string fabricName)
        {
            var allFiles = Directory.GetFiles(GetFullPath(fabricName));

            var fabric = new Fabric()
            {
                FabricName = fabricName,
            };

            foreach (var file in allFiles)
            {
                if (file.EndsWith("fabric.json"))
                {
                    var fileBytes = await File.ReadAllBytesAsync(file);
                    var details = JsonSerializer.Deserialize<FabricDetails>(fileBytes);

                    fabric.FabricId = new BigInteger(details.FabricId);
                    fabric.RootCACertificateId = new BigInteger(details.RootCertificateId);
                    fabric.RootNodeId = new BigInteger(details.RootNodeId);
                    fabric.AdminVendorId = details.AdminVendorId;
                    fabric.IPK = details.IPK;
                    fabric.OperationalIPK = details.OperationalIPK;
                    fabric.RootKeyIdentifier = details.RootKeyIdentifier;
                    fabric.CompressedFabricId = details.CompressedFabricId;
                }
                else if (file.EndsWith("rootCertificate.pem"))
                {
                    PemReader pemReader = new PemReader(new StreamReader(file));
                    fabric.RootCACertificate = pemReader.ReadObject() as X509Certificate;
                }
                else if (file.EndsWith("rootKeyPair.pem"))
                {
                    PemReader pemReader = new PemReader(new StreamReader(file));
                    fabric.RootCAKeyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                }
                else if (file.EndsWith("operationalCertificate.pem"))
                {
                    PemReader pemReader = new PemReader(new StreamReader(file));
                    fabric.OperationalCertificate = pemReader.ReadObject() as X509Certificate;
                }
                else if (file.EndsWith("operationalKeyPair.pem"))
                {
                    PemReader pemReader = new PemReader(new StreamReader(file));
                    fabric.OperationalCertificateKeyPair = pemReader.ReadObject() as AsymmetricCipherKeyPair;
                }
            }

            var allDirectories = Directory.GetDirectories(GetFullPath(fabricName));

            foreach (var directory in allDirectories)
            {
                var nodeId = new BigInteger(Path.GetFileName(directory));

                var nodeFiles = Directory.GetFiles(directory);

                foreach (var file in nodeFiles)
                {
                    if (file.EndsWith("node.json"))
                    {
                        var fileBytes = await File.ReadAllBytesAsync(file);
                        var details = JsonSerializer.Deserialize<NodeDetails>(fileBytes);

                        var node = new Node();
                        node.NodeId = nodeId;
                        node.LastKnownIpAddress = IPAddress.Parse(details.LastKnownIPAddress);
                        node.LastKnownPort = details.LastKnownPort;

                        fabric.AddNode(node);
                    }
                }
            }

            return fabric;
        }

        public async Task SaveFabricAsync(Fabric fabric)
        {
            // If we have no directory, save everything.
            //
            if (!Directory.Exists(GetFullPath(fabric.FabricName)))
            {
                Directory.CreateDirectory(GetFullPath(fabric.FabricName));

                // Create a JSON file with some of the basic information.
                //
                var details = new FabricDetails();

                details.FabricId = fabric.FabricId.ToByteArray();
                details.RootCertificateId = fabric.RootCACertificateId.ToByteArray();
                details.RootNodeId = fabric.RootNodeId.ToByteArray();
                details.AdminVendorId = fabric.AdminVendorId;
                details.IPK = fabric.IPK;
                details.OperationalIPK = fabric.OperationalIPK;
                details.RootKeyIdentifier = fabric.RootKeyIdentifier;
                details.CompressedFabricId = fabric.CompressedFabricId;

                var json = JsonSerializer.Serialize(details, new JsonSerializerOptions { WriteIndented = true });

                await File.WriteAllTextAsync(Path.Combine(_rootDirectory, fabric.FabricName, "fabric.json"), json);

                PemWriter pemWriter = new PemWriter(new StreamWriter(Path.Combine(_rootDirectory, fabric.FabricName, "rootCertificate.pem")));
                pemWriter.WriteObject(fabric.RootCACertificate);
                pemWriter.Writer.Flush();
                pemWriter.Writer.Close();

                pemWriter = new PemWriter(new StreamWriter(Path.Combine(_rootDirectory, fabric.FabricName, "rootKeyPair.pem")));
                pemWriter.WriteObject(fabric.RootCAKeyPair);
                pemWriter.Writer.Flush();
                pemWriter.Writer.Close();

                pemWriter = new PemWriter(new StreamWriter(Path.Combine(_rootDirectory, fabric.FabricName, "operationalCertificate.pem")));
                pemWriter.WriteObject(fabric.OperationalCertificate);
                pemWriter.Writer.Flush();
                pemWriter.Writer.Close();

                pemWriter = new PemWriter(new StreamWriter(Path.Combine(_rootDirectory, fabric.FabricName, "operationalKeyPair.pem")));
                pemWriter.WriteObject(fabric.OperationalCertificateKeyPair);
                pemWriter.Writer.Flush();
                pemWriter.Writer.Close();
            }

            foreach (var node in fabric.Nodes)
            {
                // Create a directory for the node if necessary.
                //
                var nodeDirectoryPath = GetFullPath(fabric.FabricName, node.NodeId);

                if (!Directory.Exists(nodeDirectoryPath))
                {
                    Directory.CreateDirectory(nodeDirectoryPath);
                }

                var nodeDetails = new NodeDetails();

                nodeDetails.NodeId = node.NodeId.ToByteArray();
                nodeDetails.LastKnownIPAddress = node.LastKnownIpAddress!.ToString();
                nodeDetails.LastKnownPort = node.LastKnownPort!.Value;

                var nodeJson = JsonSerializer.Serialize(nodeDetails, new JsonSerializerOptions { WriteIndented = true });

                await File.WriteAllTextAsync(Path.Combine(nodeDirectoryPath, "node.json"), nodeJson);
            }
        }

        private string GetFullPath(string fabricName)
        {
            var path = Path.Combine(_rootDirectory, fabricName);
            return path;
        }

        private string GetFullPath(string fabricName, BigInteger nodeId)
        {
            var path = Path.Combine(_rootDirectory, fabricName, nodeId.ToString());
            return path;
        }
    }
}
