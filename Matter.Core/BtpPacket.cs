using System;
using System.Collections;

namespace Matter.Core
{
    public class BtpPacket
    {
        public BtpPacket(bool handshake, bool management, bool acknowledgement, bool beginning, bool end, byte ackNumber, byte sequenceNumber, short messageLength, byte[] payload)
        {
            Bytes = new byte[6 + payload.Length];

            BitArray header = new BitArray(8);
            header[1] = handshake;
            header[2] = management;
            header[4] = acknowledgement;
            header[5] = end;
            header[7] = beginning;

            header.CopyTo(Bytes, 0);

            Bytes[1] = 0x0;
            Bytes[2] = ackNumber;
            Bytes[3] = sequenceNumber;
            
            // Length is two bytes!
            //
            BitConverter.GetBytes(messageLength).CopyTo(Bytes, 4);

            payload.CopyTo(Bytes, 6);
        }

        public byte[] Bytes { get; }
    }
}