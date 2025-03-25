namespace Matter.Core
{
    [Flags]
    public enum MessageFlags : byte
    {
        MessageFormatVersionOne = 0x00,
        SourceNodeID = 0x04,
    }
}