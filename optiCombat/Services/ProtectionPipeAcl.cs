using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;

namespace optiCombat.Services;

/// <summary>Crée un pipe nommé avec ACL (SYSTEM, Administrateurs, utilisateurs authentifiés).</summary>
[SupportedOSPlatform("windows")]
internal static class ProtectionPipeAcl
{
    private const uint PipeAccessDuplex = 0x00000003;
    private const uint FileFlagOverlapped = 0x40000000;
    private const uint PipeTypeByte = 0x00000000;
    private const uint PipeWait = 0x00000000;
    private const uint PipeUnlimitedInstances = 255;

    internal static NamedPipeServerStream CreateListeningStream(string pipeName)
    {
        var security = BuildPipeSecurity();
        var sdBytes = security.GetSecurityDescriptorBinaryForm();
        var sdPtr = Marshal.AllocHGlobal(sdBytes.Length);

        try
        {
            Marshal.Copy(sdBytes, 0, sdPtr, sdBytes.Length);
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = sdPtr,
                InheritHandle = false,
            };

            var handle = CreateNamedPipe(
                @"\\.\pipe\" + pipeName,
                PipeAccessDuplex | FileFlagOverlapped,
                PipeTypeByte | PipeWait,
                PipeUnlimitedInstances,
                4096,
                4096,
                0,
                ref attributes);

            if (handle.IsInvalid)
                throw new Win32Exception(Marshal.GetLastWin32Error());

            return new NamedPipeServerStream(PipeDirection.InOut, true, false, handle);
        }
        finally
        {
            Marshal.FreeHGlobal(sdPtr);
        }
    }

    private static PipeSecurity BuildPipeSecurity()
    {
        var security = new PipeSecurity();
        AddAllow(security, WellKnownSidType.LocalSystemSid, PipeAccessRights.FullControl);
        AddAllow(security, WellKnownSidType.BuiltinAdministratorsSid, PipeAccessRights.FullControl);
        AddAllow(security, WellKnownSidType.AuthenticatedUserSid, PipeAccessRights.ReadWrite);
        return security;
    }

    private static void AddAllow(PipeSecurity security, WellKnownSidType sidType, PipeAccessRights rights) =>
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(sidType, null),
            rights,
            AccessControlType.Allow));

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafePipeHandle CreateNamedPipe(
        string name,
        uint openMode,
        uint pipeMode,
        uint maxInstances,
        uint outBufferSize,
        uint inBufferSize,
        uint defaultTimeout,
        ref SecurityAttributes securityAttributes);
}
