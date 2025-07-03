namespace Matter.Core.Sessions
{
    public interface ISession
    {
        IConnection Connection { get; }

        ulong SourceNodeId { get; }

        ulong DestinationNodeId { get; }

        ushort SessionId { get; }

        ushort PeerSessionId { get; }

        bool UseMRP { get; }

        MessageExchange CreateExchange();

        byte[] Encode(MessageFrame message);

        MessageFrame Decode(MessageFrameParts messageFrameParts);

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] payload);

        void Close();

        IConnection CreateNewConnection();
    }
}
