// A real Windows service runs the official single-job listener as NetworkService.
// It is deliberately separate from the Azure agent and the administrator's SSH session.
using System;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Threading;
using System.Text.RegularExpressions;

public sealed class RunnerLauncher : ServiceBase {
    Process listener;
    protected override void OnStart(string[] arguments) {
        string config = File.ReadAllText(@"C:\ci-runner\jit.config").Trim();
        // GitHub's JIT value is base64, so it cannot add command-line switches.
        if (!Regex.IsMatch(config, @"\A[A-Za-z0-9+/]+={0,2}\z"))
            throw new Exception("Invalid single-use configuration");
        Convert.FromBase64String(config);
        File.Delete(@"C:\ci-runner\jit.config");
        ProcessStartInfo start = new ProcessStartInfo(@"C:\ci-runner\bin\Runner.Listener.exe");
        start.Arguments = "run --jitconfig " + config;
        start.WorkingDirectory = @"C:\ci-runner";
        start.UseShellExecute = false;
        start.CreateNoWindow = true;
        listener = new Process {StartInfo = start, EnableRaisingEvents = true};
        listener.Exited += delegate {ThreadPool.QueueUserWorkItem(delegate {Stop();});};
        if (!listener.Start()) throw new Exception("Runner listener could not start");
    }
    protected override void OnStop() {
        // SCM stop and a listener exit may race. Only one callback owns disposal.
        Process stopped = Interlocked.Exchange(ref listener, null);
        if (stopped != null) {
            stopped.EnableRaisingEvents = false;
            if (!stopped.HasExited) stopped.Kill();
            stopped.Dispose();
        }
    }
    public static void Main() {
        ServiceBase.Run(new RunnerLauncher {ServiceName = "WindowsCiRunner"});
    }
}
