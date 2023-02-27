using System;
using System.Collections.Generic;
using System.Text;

namespace ColdBear.Climenole
{
    public class MatterTLV
    {
        private List<byte> _values = new();

        public MatterTLV AddBooleanTrue()
        {
            _values.Add(0x09);
            return this;
        }

        public MatterTLV AddBooleanFalse()
        {
            _values.Add(0x09);
            return this;
        }

        public MatterTLV AddOctetString(string v)
        {
            _values.Add(0x10);
            _values.Add((byte)v.Length);
            _values.AddRange(Encoding.ASCII.GetBytes(v));
            return this;
        }

        public MatterTLV AddUnsignedOneOctetInteger(int v)
        {
            _values.Add(0x04);
            _values.Add((byte)v);
            return this;
        }

        public MatterTLV AddUnsignedTwoOctetInteger(short v)
        {
            _values.Add(0x04);
            _values.AddRange(BitConverter.GetBytes(v));
            return this;
        }
    }
}