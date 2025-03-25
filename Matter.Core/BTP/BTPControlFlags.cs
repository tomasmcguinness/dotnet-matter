namespace Matter.Core.BTP
{
    [Flags]
    internal enum BTPControlFlags : byte
    {
        Beginning = 0x1,
        Continuing = 0x2,
        Ending = 0x4,
        Acknowledge = 0x8,
        Handshake = 0x40,
    }
}