namespace Matter.Core
{
    /// <summary>
    /// See Appendix A of the Matter Specification for the TLV encoding. 
    /// </summary>
    public class MatterTLV
    {
        private List<byte> _values = new();

        public MatterTLV()
        {
            // Empty constructor
        }

        public MatterTLV(byte[] payload)
        {
            _values = [.. payload];
        }

        public MatterTLV AddStructure()
        {
            // Anonymous i.e. has no tag number.
            _values.Add(0x15);
            return this;
        }

        public MatterTLV AddArray(long tagNumber)
        {
            // This is a Context-Specific Tag (0x01), shifted 5 bits and then OR'd with 0x16
            // to produce a context tag for Array, 1 byte long
            // 00110110
            //
            _values.Add(0x01 << 5 | 0x16);
            _values.Add((byte)tagNumber);
            return this;
        }

        public MatterTLV AddList(long tagNumber)
        {
            // This is a Context-Specific Tag (0x01), shifted 5 bits and then OR'd with 0x17
            // to produce a context tag for List, one byte long
            // 00110111
            //
            _values.Add(0x01 << 5 | 0x17);
            _values.Add((byte)tagNumber);
            return this;
        }

        public MatterTLV EndContainer()
        {
            _values.Add(0x18);
            return this;
        }

        public MatterTLV Add1OctetString(long tagNumber, byte[] value)
        {
            // This is a Context-Specific Tag, shifted 5 bits and then OR'd with 10
            // to produce a context tag for Octet String, 1 bytes length
            // 00110010
            //
            _values.Add((0x01 << 5) | 0x10); // Octet String, 1-octet length
            _values.Add((byte)tagNumber);
            _values.Add((byte)(uint)value.Length);
            _values.AddRange(value);
            return this;
        }

        public MatterTLV Add4OctetString(long tagNumber, byte[] value)
        {
            // This is a context type 1, shifted 5 bits and then OR'd with 12
            // to produce a context tag for Octet String, 4 bytes
            // 00110010
            //
            _values.Add((0x01 << 5) | 0x12); // Octet String, 4-octet length
            _values.Add((byte)tagNumber);
            _values.AddRange(BitConverter.GetBytes((uint)value.Length));
            _values.AddRange(value);
            return this;
        }

        public MatterTLV AddUInt8(long tagNumber, byte value)
        {
            _values.Add((0x01 << 5) | 0x4);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.Add(value);

            return this;
        }

        public MatterTLV AddUInt16(long tagNumber, ushort value)
        {
            _values.Add((0x01 << 5) | 0x5);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.AddRange(BitConverter.GetBytes(value));

            return this;
        }

        public MatterTLV AddUInt32(long tagNumber, uint value)
        {
            _values.Add((0x01 << 5) | 0x6);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.AddRange(BitConverter.GetBytes(value));

            return this;
        }

        public MatterTLV AddUInt64(long tagNumber, ulong value)
        {
            _values.Add((0x01 << 5) | 0x7);
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
                _values.Add((0x01 << 5) | 0x09); // Boolean TRUE
            }
            else
            {
                _values.Add((0x01 << 5) | 0x08); // Boolean FALSE
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
            if (_values[_pointer++] != 0x15) // Anonymous Structure
            {
                throw new Exception("Expected Open Structure isn't there");
            }
        }

        internal void OpenStructure(int tag)
        {
            if (_values[_pointer++] != 0x35) // Tag Context Structure
            {
                throw new Exception("Expected Open Structure isn't there");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }
        }

        internal byte[] GetOctetString(int tag)
        {
            // Check the Control Octet.
            //
            int length = 0;

            if ((0x1F & _values[_pointer]) == 0x13)
            {
                //Octet String, 2 - octet length
                length = 8;
            }
            else if ((0x1F & _values[_pointer]) == 0x12)
            {
                //Octet String, 2 - octet length
                length = 4;
            }
            else if ((0x1F & _values[_pointer]) == 0x11)
            {
                //Octet String, 2 - octet length
                length = 2;
            }
            else if ((0x1F & _values[_pointer]) == 0x10) // Context Octet String, 1 - octet length
            {
                length = 1;
            }

            _pointer++;

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            ulong valueLength = 0;

            if (length == 1)
            {
                valueLength = _values[_pointer++];
            }
            else if (length == 2)
            {
                valueLength = BitConverter.ToUInt16(_values.ToArray(), _pointer);
                _pointer += 2;
            }
            else if (length == 4)
            {
                valueLength = BitConverter.ToUInt32(_values.ToArray(), _pointer);
                _pointer += 4;
            }
            else if (length == 8)
            {
                valueLength = BitConverter.ToUInt64(_values.ToArray(), _pointer);
                _pointer += 8;
            }

            var bytes = new byte[valueLength];

            Array.Copy(_values.ToArray(), _pointer, bytes, 0, (int)valueLength);

            _pointer += (int)valueLength;

            return bytes;
        }

        internal ushort GetUnsignedShort(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x05)
            {
                throw new Exception("Expected Unsigned Integer, 2-octet value");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            var value = BitConverter.ToUInt16(_values.ToArray(), _pointer);

            _pointer += 2;

            return value;
        }

        internal uint GetUnsignedInteger(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x06)
            {
                throw new Exception("Expected Unsigned Integer, 4-octet value");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            var value = BitConverter.ToUInt32(_values.ToArray(), _pointer);

            _pointer += 4;

            return value;
        }

        internal void CloseStructure()
        {
            if (_values[_pointer++] != 0x18) // End Container
            {
                throw new Exception("Expected EndContainer isn't there");
            }
        }

        internal byte[] GetBytes()
        {
            return _values.ToArray();
        }


    }
}