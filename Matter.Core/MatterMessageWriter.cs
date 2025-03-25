namespace Matter.Core
{
    class MatterMessageWriter
    {
        private MemoryStream _stream;

        public MatterMessageWriter()
        {
            _stream = new MemoryStream();
        }

        internal void Write(byte @byte)
        {
            _stream.WriteByte(@byte);
        }

        internal void Write(ushort sessionID)
        {
            _stream.Write(BitConverter.GetBytes(sessionID));
        }

        internal void Write(uint counter)
        {
            _stream.Write(BitConverter.GetBytes(counter));
        }

        internal byte[] GetBytes()
        {
            return _stream.GetBuffer();
        }

        internal void Write(byte[] bytes)
        {
            _stream.Write(bytes);
        }

        public long Length => _stream.Length;
    }
}
