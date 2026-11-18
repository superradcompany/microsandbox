# Execute an instruction in a nested guest, rather than trusting feature flags.
# Deliberately emit only OS versions and a fixed success message, not host identity.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Threading;

public static class CiWhpProbe {
    [StructLayout(LayoutKind.Sequential)]
    struct RegisterValue { public ulong Low; public ulong High; }
    [DllImport("WinHvPlatform.dll")] static extern int WHvGetCapability(uint code, out ulong value, uint size, out uint written);
    [DllImport("WinHvPlatform.dll")] static extern int WHvCreatePartition(out IntPtr partition);
    [DllImport("WinHvPlatform.dll")] static extern int WHvSetPartitionProperty(IntPtr partition, uint code, ref uint value, uint size);
    [DllImport("WinHvPlatform.dll")] static extern int WHvSetupPartition(IntPtr partition);
    [DllImport("WinHvPlatform.dll")] static extern int WHvDeletePartition(IntPtr partition);
    [DllImport("WinHvPlatform.dll")] static extern int WHvCreateVirtualProcessor(IntPtr partition, uint index, uint flags);
    [DllImport("WinHvPlatform.dll")] static extern int WHvDeleteVirtualProcessor(IntPtr partition, uint index);
    [DllImport("WinHvPlatform.dll")] static extern int WHvMapGpaRange(IntPtr partition, IntPtr memory, ulong address, ulong size, uint flags);
    [DllImport("WinHvPlatform.dll")] static extern int WHvSetVirtualProcessorRegisters(IntPtr partition, uint index, uint[] names, uint count, RegisterValue[] values);
    [DllImport("WinHvPlatform.dll")] static extern int WHvRunVirtualProcessor(IntPtr partition, uint index, IntPtr context, uint size);
    [DllImport("WinHvPlatform.dll")] static extern int WHvCancelRunVirtualProcessor(IntPtr partition, uint index, uint flags);
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr VirtualAlloc(IntPtr address, UIntPtr size, uint allocation, uint protection);
    [DllImport("kernel32.dll")] static extern bool VirtualFree(IntPtr address, UIntPtr size, uint type);

    static void Check(int result, string operation) {
        if (result < 0) throw new Exception(operation + " failed: 0x" + result.ToString("X8"));
    }

    public static string Run() {
        ulong capability; uint written;
        Check(WHvGetCapability(0, out capability, 8, out written), "WHvGetCapability");
        if (capability == 0) throw new Exception("WHP hypervisor is unavailable");
        IntPtr partition = IntPtr.Zero, memory = IntPtr.Zero, context = IntPtr.Zero;
        bool processorCreated = false;
        try {
            Check(WHvCreatePartition(out partition), "WHvCreatePartition");
            uint processors = 1;
            Check(WHvSetPartitionProperty(partition, 0x1fff, ref processors, 4), "Set processor count");
            Check(WHvSetupPartition(partition), "WHvSetupPartition");
            Check(WHvCreateVirtualProcessor(partition, 0, 0), "WHvCreateVirtualProcessor");
            processorCreated = true;
            memory = VirtualAlloc(IntPtr.Zero, new UIntPtr(4096), 0x3000, 4);
            if (memory == IntPtr.Zero) throw new Exception("VirtualAlloc failed");
            // Execute a real-mode HLT instruction in a fresh guest. This checks
            // nested execution, not merely the Windows feature configuration.
            Marshal.WriteByte(memory, 0, 0xf4);
            Check(WHvMapGpaRange(partition, memory, 0, 4096, 7), "WHvMapGpaRange");
            uint[] names = {0x13, 0x10, 0x11, 0x1c}; // CS, RIP, RFLAGS, CR0
            RegisterValue[] values = {
                new RegisterValue {Low=0, High=((ulong)0x9b << 48) | 0xffff},
                new RegisterValue {Low=0},
                new RegisterValue {Low=2},
                new RegisterValue {Low=0x10}
            };
            Check(WHvSetVirtualProcessorRegisters(partition, 0, names, 4, values), "Set guest registers");
            context = Marshal.AllocHGlobal(1024);
            using (ManualResetEvent drained = new ManualResetEvent(false)) {
                Timer timer = new Timer(delegate(object unused) { WHvCancelRunVirtualProcessor(partition, 0, 0); }, null, 10000, Timeout.Infinite);
                try {
                    Check(WHvRunVirtualProcessor(partition, 0, context, 1024), "WHvRunVirtualProcessor");
                } finally {
                    // A callback already in flight must finish before the partition
                    // is freed; Timer.Dispose() alone does not wait for callbacks.
                    timer.Dispose(drained);
                    drained.WaitOne();
                }
            }
            int reason = Marshal.ReadInt32(context);
            if (reason != 8) throw new Exception("Expected HLT exit, got 0x" + reason.ToString("X"));
            return "PASS: nested WHP guest executed HLT (exit reason 8)";
        } finally {
            if (processorCreated) WHvDeleteVirtualProcessor(partition, 0);
            if (partition != IntPtr.Zero) WHvDeletePartition(partition);
            if (memory != IntPtr.Zero) VirtualFree(memory, UIntPtr.Zero, 0x8000);
            if (context != IntPtr.Zero) Marshal.FreeHGlobal(context);
        }
    }
}
'@
[CiWhpProbe]::Run()
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version | ConvertTo-Json -Compress
