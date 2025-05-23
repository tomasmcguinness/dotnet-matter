﻿namespace Matter.Core
{
    [Flags]
    public enum ExchangeFlags : byte
    {
        Initiator = 0x1,
        Acknowledgement = 0x2,
        Reliability = 0x4,
        SecuredExtensions = 0x8,
        VendorPresent = 0x10,
    }
}