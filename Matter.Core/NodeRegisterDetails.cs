namespace Matter.Core
{
    public class NodeRegisterDetails
    {
        public NodeRegisterDetails(ushort discriminator, ushort port, string[] addresses)
        {
            Discriminator = discriminator;
            Port = port;
            Addresses = addresses;
        }

        public ushort Discriminator { get; set; }

        public ushort Port { get; set; }

        public string[] Addresses { get; set; } = [];
    }
}
