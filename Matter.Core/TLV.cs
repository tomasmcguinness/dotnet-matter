﻿namespace Matter.Core
{
    public class MatterTLV
    {
        private List<byte> _values = new();

        public MatterTLV AddStructure()
        {
            _values.Add(0x15);
            return this;
        }

        public MatterTLV EndContainer()
        {
            _values.Add(0x18);
            return this;
        }

        public MatterTLV AddOctetString4(long tagNumber, byte[] value)
        {
            // This is a context type 1, shifted 5 bits and then OR'd with 12
            // to produce a context tag for Octet String, 4 bytes
            // 00110010
            //
            _values.Add((0x1 << 5) | 0x12); // Octet String, 4-octet length
            _values.Add((byte)tagNumber);
            _values.Add((byte)value.Length);
            _values.AddRange(value);
            return this;
        }

        public MatterTLV AddUShort(long tagNumber, ushort value)
        {
            _values.Add((0x1 << 5) | 0x5); // Unsigned Integer, 2-octet value
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.AddRange(BitConverter.GetBytes(value));

            return this;
        }

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write(_values.ToArray());
        }

        internal void AddBool(int tagNumber, bool v2)
        {
            if (v2)
            {
                _values.Add((0x1 << 5) | 0x9); // Boolean TRUE
            }
            else
            {
                _values.Add((0x1 << 5) | 0x8); // Boolean FALSE
            }

            _values.Add((byte)tagNumber);
        }
    }
}