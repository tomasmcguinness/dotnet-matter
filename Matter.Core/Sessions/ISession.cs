namespace Matter.Core.Sessions
{
    internal interface ISession
    {
        ushort SessionId { get; }

        MessageExchange CreateExchange();

        byte[] Encode(MessageFrame message);

        MessageFrame Decode(byte[] payload);

        Task<byte[]> ReadAsync();

        Task SendAsync(byte[] payload);
    }
}
