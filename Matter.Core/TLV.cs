using System.Drawing;
using System.Net.Sockets;

namespace Matter.Core
{
    public class MatterTLV
    {
        private List<byte> _values = new();

        public MatterTLV()
        {
            // Empty constructor
        }

        public MatterTLV(byte[] payload)
        {
            _values = new List<byte>(payload);
        }

        public MatterTLV AddStructure()
        {
            // Anonymous i.e. has no tag number.
            _values.Add(0x15);
            return this;
        }

        public MatterTLV EndContainer()
        {
            _values.Add(0x18);
            return this;
        }

        public MatterTLV Add32BitOctetString(long tagNumber, byte[] value)
        {
            // This is a context type 1, shifted 5 bits and then OR'd with 12
            // to produce a context tag for Octet String, 4 bytes
            // 00110010
            //
            _values.Add((0x1 << 5) | 0x12); // Octet String, 4-octet length
            _values.Add((byte)tagNumber);
            _values.AddRange(BitConverter.GetBytes((uint)value.Length));
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

        internal void AddBool(int tagNumber, bool v2)
        {
            if (v2)
            {
                _values.Add((0x1 << 5) | 0x09); // Boolean TRUE
            }
            else
            {
                _values.Add((0x1 << 5) | 0x08); // Boolean FALSE
            }

            _values.Add((byte)tagNumber);
        }

        internal void Serialize(MatterMessageWriter writer)
        {
            var bytes = _values.ToArray();
            writer.Write(bytes);
        }


        private int _pointer = 0;

        internal void OpenStructure()
        {
            if (_values[_pointer] != 0x15)
            {
                throw new Exception("Expected Open Structure isn't there");
            }

            _pointer++;
        }

        internal byte[] GetOctetString(int tag)
        {
            // Check the Control Octet.
            //
            int length = 0;

            if ((_values[_pointer] & 0x10) != 0)
            {
                //Octet String, 1 - octet length
                length = 1;
            }

            _pointer++;

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            var valueLength = 0;

            if (length == 1)
            {
                valueLength = _values[_pointer++];
            }

            //_values.AddRange(BitConverter.GetBytes((uint)value.Length));
            //_values.AddRange(value);

            var bytes = new byte[valueLength];

            Array.Copy(_values.ToArray(), _pointer, bytes, 0, valueLength);

            _pointer += (int)valueLength;

            return bytes;
        }
    }
}