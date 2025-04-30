using System.Text;

namespace Matter.Core.TLV
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

        public MatterTLV AddStructure(byte tagNumber)
        {
            // Anonymous i.e. has no tag number.
            _values.Add(0x01 << 5 | 0x15);
            _values.Add(tagNumber);
            return this;
        }

        public MatterTLV AddArray(byte tagNumber)
        {
            // This is a Context-Specific Tag (0x01), shifted 5 bits and then OR'd with 0x16
            // to produce a context tag for Array, 1 byte long
            // 00110110
            //
            _values.Add(0x01 << 5 | 0x16);
            _values.Add(tagNumber);
            return this;
        }

        public MatterTLV AddArray()
        {
            // This is an anonymous tag, shifted 5 bits and then OR'd with 0x22
            // 00010110
            //
            _values.Add(0x16);
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

        public MatterTLV AddList()
        {
            _values.Add(0x17);
            return this;
        }

        public MatterTLV EndContainer()
        {
            _values.Add(0x18);
            return this;
        }

        // TODO Merge all these into one method, using the length of the value to determine
        // the size of the length field.
        public MatterTLV Add1OctetString(long tagNumber, byte[] value)
        {
            // This is a Context-Specific Tag, shifted 5 bits and then OR'd with 10
            // to produce a context tag for Octet String, 1 bytes length
            // 00110000
            //
            _values.Add(0x01 << 5 | 0x10); // Octet String, 1-octet length
            _values.Add((byte)tagNumber);
            _values.Add((byte)value.Length);
            _values.AddRange(value);
            return this;
        }

        public MatterTLV Add2OctetString(long tagNumber, byte[] value)
        {
            // This is a Context-Specific Tag, shifted 5 bits and then OR'd with 11
            // to produce a context tag for Octet String, 2 bytes length
            // 00110001
            //
            _values.Add(0x01 << 5 | 0x11); // Octet String, 2-octet length
            _values.Add((byte)tagNumber);
            _values.AddRange(BitConverter.GetBytes((ushort)value.Length));
            _values.AddRange(value);
            return this;
        }

        public MatterTLV Add4OctetString(long tagNumber, byte[] value)
        {
            // This is a context type 1, shifted 5 bits and then OR'd with 12
            // to produce a context tag for Octet String, 4 bytes
            // 00110010
            //
            _values.Add(0x01 << 5 | 0x12); // Octet String, 4-octet length
            _values.Add((byte)tagNumber);
            _values.AddRange(BitConverter.GetBytes((uint)value.Length));
            _values.AddRange(value);
            return this;
        }

        public MatterTLV AddUInt8(long tagNumber, byte value)
        {
            _values.Add(0x01 << 5 | 0x4);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.Add(value);

            return this;
        }

        public MatterTLV AddUInt16(long tagNumber, ushort value)
        {
            _values.Add(0x01 << 5 | 0x5);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.AddRange(BitConverter.GetBytes(value));

            return this;
        }

        public MatterTLV AddUInt32(long tagNumber, uint value)
        {
            _values.Add(0x01 << 5 | 0x6);
            _values.Add((byte)tagNumber);

            // No length required.
            //
            _values.AddRange(BitConverter.GetBytes(value));

            return this;
        }

        public MatterTLV AddUInt64(long tagNumber, ulong value)
        {
            _values.Add(0x01 << 5 | 0x7);
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
                _values.Add(0x01 << 5 | 0x09); // Boolean TRUE
            }
            else
            {
                _values.Add(0x01 << 5 | 0x08); // Boolean FALSE
            }

            _values.Add((byte)tagNumber);
        }

        internal void Serialize(MatterMessageWriter writer)
        {
            var bytes = _values.ToArray();
            writer.Write(bytes);
        }

        private int _pointer = 0;

        public void OpenStructure()
        {
            if (_values[_pointer++] != 0x15) // Anonymous Structure
            {
                throw new Exception("Expected Structure not found");
            }
        }

        public void OpenStructure(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x15) // Tag Context Structure
            {
                throw new Exception("Expected Structure not found");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }
        }

        public void OpenArray(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x16) // Context Array
            {
                throw new Exception("Expected Array not found");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }
        }

        public void OpenList(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x17) // Context List
            {
                throw new Exception("Expected List not found");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }
        }

        public bool GetBoolean(int tag)
        {
            var selectedByte = _values[_pointer++];

            if (selectedByte != 0x28 && selectedByte != 0x29) // Context Boolean (false)
            {
                throw new Exception("Expected Boolean not found");
            }

            bool value = selectedByte == 0x29; // True

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            return value;
        }

        public byte[] GetOctetString(int tag)
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

        public byte GetUnsignedInt8(int tag)
        {
            if ((0x1F & _values[_pointer++]) != 0x04)
            {
                throw new Exception("Expected Unsigned Integer, 1-octet value not found");
            }

            if (_values[_pointer++] != (byte)tag)
            {
                throw new Exception("Expected tag number not found");
            }

            byte value = _values[_pointer++];

            return value;
        }

        public ushort GetUnsignedInt16(int tag)
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

        internal uint GetUnsignedInt32(int tag)
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

        public void CloseContainer()
        {
            if (_values[_pointer++] != 0x18) // End Container
            {
                throw new Exception("Expected EndContainer not found");
            }
        }

        internal byte[] GetBytes()
        {
            return _values.ToArray();
        }

        public override string ToString()
        {
            var sb = new StringBuilder();

            var indentation = 0;

            var indent = (StringBuilder sb) =>
            {
                for (int x = 0; x < indentation; x++)
                {
                    sb.Append(" ");
                }
            };

            var renderTag = (byte[] bytes, int index) =>
            {
                int tagControl = bytes[index] >> 5;
                int elementType = bytes[index] >> 0 & 0x1F;

                int length = 1; // We have read the tagControl/elementType byte

                sb.Append("|");
                indent(sb);

                try
                {
                    if (elementType == 0x15) // Structure
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        sb.AppendLine("Structure {");
                        indentation += 2;
                    }

                    else if (elementType == 0x16)
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        sb.AppendLine("Array {");
                        indentation += 2;
                    }

                    else if (elementType == 0x17)
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        sb.AppendLine("List {");
                        indentation += 2;
                    }

                    else if (elementType == 0x07) // Unsigned Integer 64bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = BitConverter.ToUInt64(bytes, index + length);

                        sb.AppendLine($"Unsigned Int (64bit) ({value})");

                        length += 8;
                    }

                    else if (elementType == 0x06) // Unsigned Integer 32bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = BitConverter.ToUInt32(bytes, index + length);

                        sb.AppendLine($"Unsigned Int (32bit) ({value})");

                        length += 4;
                    }

                    else if (elementType == 0x05) // Unsigned Integer 16bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = BitConverter.ToUInt16(bytes, index + length);

                        sb.AppendLine($"Unsigned Int (16bit) ({value}|0x{value:X2})");

                        length += 2;
                    }

                    else if (elementType == 0x04) // Unsigned Integer 8bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = bytes[index + length];

                        sb.AppendLine($"Unsigned Int (8bit) ({value}|0x{value:X2})");

                        length += 1;
                    }

                    else if (elementType == 0x01) // Signed Integer 16bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = BitConverter.ToInt16(bytes, index + length);

                        sb.AppendLine($"Signed Int (16bit) ({value}|0x{value:X2})");

                        length += 2;
                    }

                    else if (elementType == 0x00) // Signed Integer 8bit 
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        var value = bytes[index + length];

                        sb.AppendLine($"Signed Int (8bit) ({value}|0x{value:X2})");

                        length += 1;
                    }

                    else if (elementType == 0x0C) // UTF-8 String, 1-octet length
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        // One octet length
                        var stringLength = bytes[index + length];

                        length++;

                        var value = Encoding.UTF8.GetString(bytes.AsSpan().Slice(index + length, stringLength));

                        sb.AppendLine($"UTF-8 String, 1-octet length ({value})");

                        length += 1;
                    }

                    else if (elementType == 0x0E) // UTF-8 String, 4-octet length
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");

                            length++;
                        }
                        else if (tagControl == 0x02) // Common Profile Tag Form, 2 octets
                        {
                            var tag = BitConverter.ToInt16(bytes, index + length);
                            sb.Append($"{tag} => ");

                            length += 2;
                        }
                        else if (tagControl == 0x03) // Common Profile Tag Form, 4 octets
                        {
                            var tag = BitConverter.ToInt32(bytes, index + length);
                            sb.Append($"{tag} => ");

                            length += 4;
                        }

                        // One octet length
                        var stringLength = BitConverter.ToUInt32(bytes, index + length);

                        length += 4;

                        var value = Encoding.UTF8.GetString(bytes.AsSpan().Slice(index + length, (int)stringLength));

                        sb.AppendLine($"UTF-8 String, 4-octet length ({value})");

                        length += 1;
                    }

                    else if (elementType == 0x10) // Octet String, 1-octet length
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        // One octet length
                        var stringLength = bytes[index + length];

                        length++;

                        var value = bytes.AsSpan().Slice(index + length, stringLength).ToArray();

                        sb.AppendLine($"Octet String, 1-octet length ({BitConverter.ToString(value)})");

                        length += stringLength;
                    }

                    else if (elementType == 0x08 || elementType == 0x09) // Boolean
                    {
                        if (tagControl == 0x01) // Context {
                        {
                            sb.Append($"{bytes[index + 1].ToString()} => ");
                            length++;
                        }

                        sb.AppendLine($"Boolean ({elementType == 0x09})");
                    }

                    else if (elementType == 0x18)
                    {
                        indentation -= 2;
                        sb.AppendLine("}");
                    }

                    else
                    {
                        sb.AppendLine($"Unhandled Tag ({tagControl:X2}|{elementType:X2})");
                    }
                }
                catch
                {

                }

                return length;
            };

            // Move through each
            //
            var bytes = GetBytes();

            sb.AppendLine("TLV Payload");
            sb.AppendLine();
            sb.AppendLine(BitConverter.ToString(bytes).Replace("-", ""));
            sb.AppendLine();

            var i = 0;

            while (i < bytes.Length)
            {
                i += renderTag(bytes, i);
            }

            return sb.ToString();
        }
    }
}