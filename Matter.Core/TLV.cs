using System.Text;

namespace Matter.Core
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

        public MatterTLV AddOctetString4(long tagNumber, byte[] value)
        {
            // This is a context type 1, shifted 5 bits and then OR'd with 12
            // to produce a context tag for Octet String, 4 bytes
            // 00110010
            //
            _values.Add((byte)(((byte)0x1 << 5) | 0x12));
            _values.Add((byte)tagNumber);
            _values.Add((byte)value.Length);
            _values.AddRange(value);
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

        internal void Serialize(MatterMessageWriter writer)
        {
            writer.Write(_values.ToArray());
        }

        internal void AddBytes(int tagNumber, byte[] bytes, int v2, int v3)
        {
            _values.Add((byte)tagNumber);
            _values.Add((byte)(uint)bytes.Length);
            _values.AddRange(bytes);
        }
    }
}